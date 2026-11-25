/**
 * JWT-VP（JWS）として W3C VP を検証する最小プリミティブ。
 *
 * `verifyCredential`（`vc/verify.ts`）と同じ JWS プリミティブ（`decodeCompactJws` /
 * `verifyWithJwk`）を再利用し、`alg=none`（3011）・署名不一致（3010）を拒否、`iss === holder`・
 * `aud` / `nonce` の整合（OID4VP の Holder Binding。不一致は 3012）を検証する。`jose` は使わない。
 * 署名（発行）側は `issue.ts` が担う。`alg` 検証・署名検証は `presentation-signature.ts` に切り出して
 * あり（分離しているのはファイル行数上限（300 行）のため）、本ファイルは
 * `verifyPresentationClaims` / `verifyPresentation` のオーケストレーションに専念する。
 *
 * SDK の JWT-VP 形式では、W3C VC Data Model v2.0 の VP を JWT ペイロードの `vp` クレームに格納する。
 *
 * 含まれる各 VC（`vp.verifiableCredential`）も検証し `credentialResults`
 * として返す。実体・設計根拠・fail-closed 方針は `credential-results.ts` を見ること。
 * 失敗は例外にせず `valid: false` で返すため、呼び出し側は **`valid` を必ず確認する**。
 * `opts.issuerTrust` / `clockSkewSeconds` は内包 VC の検証へ中継する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・VC 本文・開示値・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PresentationWorkBudget } from '../../primitives/presentation-work-budget.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { TrustedIssuerList } from '../../trusted-issuer/types.js';
import type { IssuerTrustOption } from '../issuer-key-revocation.js';
import { assertTimeClaims, resolveClockSkewSeconds } from '../time-claims.js';
import { assertAlg, decodeCompactJwsOrThrow } from '../vc/jws.js';
import {
  type EmbeddedCredentialKeyResolver,
  type PresentationVerificationFields,
  resolvePresentationVerificationFields,
} from './credential-results.js';
import { assertSignature, type PresentationVerifierKey } from './presentation-signature.js';
import type { AssertedVerifiablePresentation, VerifiablePresentation } from './vp.js';
import { assertVpClaims } from './vp-claims.js';

/** `verifyPresentation` の検証鍵注入方法（`presentation-signature.ts` にある）。 */
export type { PresentationVerifierKey } from './presentation-signature.js';

/** `verifyPresentation` の入力オプション。 */
export interface VerifyPresentationOptions {
  /** holder 公開鍵 JWK or 検証関数。 */
  readonly key: PresentationVerifierKey;
  /**
   * 期待する Verifier 識別子（OID4VP の `aud`）。既定（束縛）モードでは必須で、payload の `aud` と
   * 一致を要求する。`allowUnbound: true` 時は指定された場合のみ照合する。
   */
  readonly expectedAudience?: string;
  /**
   * 期待する nonce（リプレイ対策）。既定（束縛）モードでは必須で、payload の `nonce` と一致を要求する。
   * `allowUnbound: true` 時は指定された場合のみ照合する。
   */
  readonly expectedNonce?: string;
  /**
   * 現在時刻（エポック秒）。`iat` / `exp` / `nbf` 評価に用いる。既定は現在時刻。テストの決定性のため注入可能。
   */
  readonly nowSeconds?: number;
  /**
   * `iat` / `exp` / `nbf` 評価で許容するクロックスキュー秒数。既定 = 上限キャップ
   * `CLOCK_SKEW_PROFILE.vp`（30s）。0 以上 30 以下の整数のみ指定でき、
   * それ以外（キャップ超過・負値・非整数・非数値）は `CLOCK_SKEW_OPTION_INVALID`（4015）で拒否する。
   * VP のキャップは VC（120s）より厳しい点に注意する。`0` 指定時、`exp` / `nbf` の判定は本オプション
   * 導入前と同一になる（`iat` の評価は本プロファイルで新設したものであり、`0` でも評価される）。
   */
  readonly clockSkewSeconds?: number;
  /**
   * Verifier バインド（`aud` / `nonce`）を必須としない unsafe モード。既定 `false`（必須）。
   * OID4VP 文脈外で verifier バインドを持たない VP を検証する場合に明示的にオプトインする。
   * `true` の場合でも `expectedAudience` / `expectedNonce` を指定すれば従来どおり照合する。
   */
  readonly allowUnbound?: boolean;
  /**
   * 内包 VC（`vp.verifiableCredential`）の発行者検証鍵を返す DI コールバック。
   * 未指定なら内包 VC は全件 `valid: false`（fail-closed）。DID 解決を持つ上位が配線する。
   */
  readonly credentialKey?: EmbeddedCredentialKeyResolver;
  /**
   * 発行者について構築済みの Federation Trust Chain（FC-11）。
   *
   * VP 署名自体には適用せず、内包 VC の検証へそのまま中継する。
   */
  readonly issuerTrust?: IssuerTrustOption;
  /**
   * 内包 VC が提示者（`vp.holder`）のものであることを要求する。
   * 既定 `false`（後方互換。従来どおり発行者署名・時刻・FC-11 までしか見ない）。
   *
   * `true` のとき、内包 VC ごとに次を要求し、満たさない VC は `credentialResults[].errors` に
   * `3012` を載せて `valid: false` にする（例外にはしない）:
   *
   * - JWT-VC: `sub === vp.holder`。**`sub` を持たない VC（bearer）は拒否する**。
   * - SD-JWT VC: `requireKeyBinding: true` として `cnf` と KB-JWT を検証する。
   *
   * **`true` のときは実効 `audience` / `nonce` の両方を要求する（fail-closed）。** どちらかが
   * `undefined` だと内包 SD-JWT VC は KB-JWT の内容によらず `3012` で `valid: false` になる
   * （`undefined` は「照合しない」ではない）。委譲先の KB-JWT 検証は期待値未指定の項目の照合を
   * 丸ごとスキップするため、通すと鍵保持だけで突合成立と報告してしまうからである。
   * `allowUnbound: true` と併用して `expectedAudience` / `expectedNonce` を省略した呼び出しが
   * これに該当する。内包 JWT-VC の `sub` 突合は `aud` / `nonce` を使わないため対象外。
   *
   * 委任された提示（`sub !== vp.holder`）は `3012` になる。独自の委任材料による突合
   * （旧 `delegations` オプション）は削除した。
   */
  readonly requireHolderBinding?: boolean;
  /**
   * Trusted Issuer List。
   *
   * 内包 VC（`vp.verifiableCredential`）ごとに `issuerDID` を本リストと照合し、
   * `credentialResults[].isTrustedIssuer` に反映する opt-in の DI。**未指定（既定）なら従来どおり
   * 照合を行わず `null`（未実行）を返す**（`credentialKey` / `issuerTrust` と同じ DI パターン）。
   * 複数リストを横断して照合したい場合は、呼び出し側でリストをマージしてから渡すこと
   * （本 API は 1 リストしか受け取らない）。
   */
  readonly trustedIssuerList?: TrustedIssuerList;
  /**
   * VP 1 通で共有する仕事量の残予算（`newPresentationWorkBudget()`）。
   *
   * 内包 VC の署名検証・issuer 信頼評価（`trustedIssuerList` の走査）がこれを消費する。同じ予算を
   * `verifyCredentialChainOnPresentation` の `workBudget` や `validateClaimsAgainstTypeMetadata` の
   * `workBudget` にも渡すと、VP 全体で合算した仕事量を縛れる。**未指定なら本呼び出し専用の予算を作る**。
   * 超過は fail-closed の例外（`3002` / `4051` / `3061`）で VP 全体を拒否する。
   */
  readonly workBudget?: PresentationWorkBudget;
}

/**
 * 検証成功時に返す JWT-VP の構成要素と、内包 VC の検証結果。**`valid` が
 * 保証しない範囲**（既定は内包 VC の提示者突合をしない）は継承元の JSDoc を参照。
 */
export interface VerifiedPresentation extends PresentationVerificationFields {
  /** デコード済み JWS ヘッダ。 */
  readonly header: Record<string, unknown>;
  /** デコード済み JWS ペイロード（`iss` / `aud` / `nonce` / `vp` 等）。 */
  readonly payload: Record<string, unknown>;
  /** 構造検証済みの VP（payload.vp）。 */
  readonly presentation: VerifiablePresentation;
}

/**
 * VP レベルの検証だけを終えた中間結果（内包 VC は未検証）。`verifyPresentationClaims` の戻り値。
 *
 * 内包 VC 検証を後段へ委ねる呼び出し側が使う内部型で、`credentialResults` を**持たない**。VP は
 * `presentation` ではなく検査済みメンバごと（`asserted`）持ち回り、下流に `vp.holder` /
 * `vp.verifiableCredential` を読み直させない（own アクセサ付き VP なら 2 度目が別の値を返し得る）。
 */
export interface VerifiedPresentationClaims
  extends Omit<VerifiedPresentation, keyof PresentationVerificationFields | 'presentation'> {
  /** 構造検証済みの VP（本体は `asserted.vp`）と、その検証に使った own メンバ。 */
  readonly asserted: AssertedVerifiablePresentation;
  /**
   * 時刻評価に用いた基準時刻（エポック秒。`nowSeconds` 未指定なら解決済みの現在時刻）。
   * 後段の内包 VC 検証も同じ値で評価させるために返す（取り直すと VP と内包 VC で時刻がずれる）。
   */
  readonly nowSeconds: number;
}

/**
 * JWT-VP の VP レベル検証だけを行い、**内包 VC は検証しない**内部経路。
 *
 * `verifyPresentation` の前半（`alg` / 署名 / 時刻 / 提示バインド）そのもので、`credentialResults`
 * を組み立てない点だけが異なる。**公開 API ではない**（`exports/` から出していない）。
 * 分けているのは内包 VC 検証を**提示 1 件につき 1 回だけ**走らせるため。replay ガード
 * （`auth/nonce/vp-guard.ts`）と Wallet ファサードはどちらも、VP 署名の検証後でないと確定しない値
 * （束縛照合を終えた実効 `aud` / DID 解決で補完した発行者鍵）で内包 VC を評価する。
 * `verifyPresentation` をそのまま呼ぶとその結果を捨てて評価し直すことになり、同じ VC への
 * 暗号検証と `credentialKey` コールバックが二重・三重に走る。
 *
 * @param jwt 検証対象のコンパクト JWT-VP 文字列。
 * @param opts `verifyPresentation` と同じオプション（`credentialKey` は本関数では使わない）。
 * @returns ヘッダ・ペイロード・構造検証済み VP（検査済みメンバごと）と、解決済みの基準時刻。
 * @throws `verifyPresentation` と同じ（内包 VC 由来の失敗は例外にならない）。
 */
export function verifyPresentationClaims(
  jwt: string,
  opts: VerifyPresentationOptions,
): VerifiedPresentationClaims {
  // オプション検証は署名検証（暗号処理）より前に済ませる（fail fast）。
  // 任意オプションは自身のプロパティに限って読む。継承値を拾うと、`nowSeconds` を省略した
  // 正当な検証で **`Object.prototype.nowSeconds` の過去時刻が「現在時刻」として使われ、
  // exp 超過の失効済み VP が受理される**。`clockSkewSeconds` も同様に、未指定なのに汚染値が
  // 許容スキューとして適用されると時刻検証の窓が呼び出し側の意図より広がる。
  const skewSeconds = resolveClockSkewSeconds('vp', ownProperty<number>(opts, 'clockSkewSeconds'));
  const nowSeconds = ownProperty<number>(opts, 'nowSeconds');
  // `key` は必須プロパティだが、型の無い JS から渡し忘れた場合 `opts.key` は継承値を拾う。
  // 修正前は `undefined.publicKeyJwk` で TypeError（fail-close）だったところが、
  // `Object.prototype.key` 汚染下では **攻撃者が選んだ鍵での署名検証**に変わる。自身の
  // プロパティとして存在しない / オブジェクトでない場合は署名検証不成立（3010）へ正規化する。
  const key = ownProperty<PresentationVerifierKey>(opts, 'key');
  if (key === null || typeof key !== 'object') {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // 構造不正は 2001（DID 解決失敗）ではなく VP 検証 API の失敗面（3010）へ正規化する。
  const decoded = decodeCompactJwsOrThrow(jwt, ErrorCodes.SIG_INVALID);
  const alg = assertAlg(decoded.header, { allowEs256kR: true });
  assertSignature(alg, decoded, key);
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  assertTimeClaims(decoded.payload, now, skewSeconds);
  return {
    header: decoded.header,
    payload: decoded.payload,
    asserted: assertVpClaims(decoded.payload, opts),
    nowSeconds: now,
  };
}

/**
 * JWT-VP（コンパクト JWS）を検証する。
 *
 * `issuePresentation` で署名した JWT-VP を検証し、デコード済みヘッダ・ペイロードと構造検証済み VP を
 * 返す。holder 公開鍵 or 検証関数は `opts.key` で DI する（holder DID 解決は credential の責務外）。
 * 含まれる各 VC も検証し、結果を `credentialResults` に返す（発行者鍵は `opts.credentialKey` で DI。
 * 未指定なら当該 VC は検証不能として `valid: false`）。内包 VC の失敗は例外にならないため、
 * 呼び出し側は戻り値の `valid` を必ず確認すること。**内包 VC を 1 件も含まない VP も `valid: false`**
 * （`errors` に `3002`）。何も証明しない提示を `every([])` の空真で通さない。
 *
 * 既定では Verifier バインド（`aud` / `nonce`）を必須とし、`expectedAudience` / `expectedNonce` の
 * 未指定や不一致を拒否する（OID4VP のリプレイ・対象者バインド未検証を防ぐ）。バインドを持たない VP を
 * 検証する場合は `allowUnbound: true` で明示的にオプトアウトする。`iat` / `exp` / `nbf` の時刻評価も
 * `clockSkewSeconds`（既定 30s）込みで行う。
 *
 * 内包 VC が提示者のものかは既定では検証しない。要求する場合は `requireHolderBinding: true` を
 * 指定する（不成立の VC は例外ではなく `credentialResults[].errors` の `3012` として報告される）。
 *
 * @param jwt 検証対象のコンパクト JWT-VP 文字列。
 * @param opts 検証鍵・期待 audience / nonce・現在時刻・クロックスキュー・allowUnbound。
 * @returns デコード済みヘッダ・ペイロード・構造検証済み VP と内包 VC の検証結果。
 * @throws `clockSkewSeconds` 不正（code `4015`）/ 形式不正（code `3010`）/ `alg=none`（code `3011`）/
 *         署名不一致（code `3010`）/ 未来 `iat` のスキュー超過（code `4014`）/ 期限切れ（code `3024`）/
 *         有効化前（code `3025`）/ VP 構造不正・時刻型不正（code `3002`）/
 *         holder・aud・nonce 不整合・バインド未指定（Holder Binding 不一致、code `3012`）の場合（VericertsError）。
 */
export function verifyPresentation(
  jwt: string,
  opts: VerifyPresentationOptions,
): VerifiedPresentation {
  const { header, payload, asserted, nowSeconds } = verifyPresentationClaims(jwt, opts);
  // 内包 VC の検証。検査済みメンバ（`asserted`）をそのまま渡して VP を
  // 読み直させない。オプションの読み方は `credential-results.ts` が決める。
  return {
    header,
    payload,
    presentation: asserted.vp,
    ...resolvePresentationVerificationFields(asserted, opts, nowSeconds),
  };
}
