/**
 * SD-JWT / SD-JWT VC の検証と Key Binding JWT（KB-JWT）の生成・検証プリミティブ。
 *
 * IETF draft-ietf-oauth-selective-disclosure-jwt / draft-ietf-oauth-sd-jwt-vc 準拠。
 *
 * 検証手順（`verifySdJwt`）:
 * 1. SD-JWT を分解（`parseSdJwt`）。
 * 2. Issuer-signed JWT をデコードし `alg=none`（3011）・未対応 alg・署名不一致（3010）を拒否。
 * 3. 署名確定後にヘッダの `typ` を検証する。あれば `dc+sd-jwt` / `vc+sd-jwt` のいずれかであること
 *    を確認する（移行期間の双方受理）。それ以外は 3002（`kb+jwt` / `JWT` 等との typ 混同を塞ぐ）。
 *    `typ` 欠落は受理する（`typ` は署名対象なので剥奪・改変は署名検証失敗を伴い、欠落拒否は防御を
 *    足さない）。
 * 4. `issuerTrust` 指定時のみ FC-11 の鍵無効化突合（`issuer-key-revocation.ts`。5012 / 5010）。
 * 5. Issuer payload の `vct` を取り出し、`expectedVct` 指定時は照合する（不一致は 3010）。
 * 6. Issuer payload の `iat` / `exp` / `nbf` を `clockSkewSeconds`（既定 120s）込みで評価
 *    する。未来 `iat` のスキュー超過は 4014、期限切れは 3024、有効化前は 3025、型不正は 3002
 *    （JWT-VC `verify.ts` と完全に同じ挙動。フォーマット間の時刻検証 bypass を塞ぐ）。
 * 7. 同梱された各 Disclosure の digest が Issuer payload の `_sd` 配列に含まれるか照合
 *    （改竄・欠落は 3010）。照合できた Disclosure を平文クレームへ復元する。
 * 8. KB-JWT がある場合: payload の `cnf.jwk` で KB-JWT 署名を検証し、`aud` / `nonce` / `sd_hash`
 *    の整合を確認する（Holder Binding 不一致は 3012）。KB-JWT の `iat` は常に
 *    `min(clockSkewSeconds, 30)` でスキュー評価し、超過は 4014。
 *    `aud` / `nonce` は期待値（`audience` / `nonce`）が指定された項目だけを照合する。ただし
 *    `requireKeyBinding: true` の場合は両方の指定が**必須**で、欠けていれば暗号処理へ入る前に
 *    3012 になる。鍵の保持に加え、提示先とセッションへの束縛を確認する。
 *
 * SD-JWT VC 固有:
 * - `vct` の照合（期待値が指定された場合）。不一致は 3010（VC 構造の信頼不一致）。
 * - `cnf` の保持と KB-JWT 検証への供給。
 * - `status`（Token Status List 参照）の保持と、参照解決インターフェース（`resolveStatus`）。
 *   実際の失効ビット評価は issuer ドメインの責務。未対応（status 未設定）時は 3018。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に salt・開示値・公開鍵・JWT を含めない。
 * - @noble / Web Crypto 由来例外は cause を渡さず `VericertsError` に正規化する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { assertSigningKeyNotRevoked, type IssuerTrustOption } from '../issuer-key-revocation.js';
import { assertTimeClaims, CLOCK_SKEW_PROFILE, resolveClockSkewSeconds } from '../time-claims.js';
import type { CredentialAlg, DecodedJws } from '../vc/jws.js';
import { assertAlg, decodeCompactJwsOrThrow, verifyWithJwkOrFalse } from '../vc/jws.js';
import type { CredentialSigner } from '../vc/signer.js';
import { recoverClaims, validateCnf, validateStatus } from './claims.js';
import {
  attachKeyBindingSignature,
  computeSdHash,
  createKeyBindingTemplate,
  type KeyBindingOptions,
} from './key-binding.js';
import { assertBindingExpectationsPresent, assertKeyBinding } from './key-binding-verify.js';
import type { ConfirmationClaim, StatusReference } from './sdjwt.js';
import { parseSdJwt } from './sdjwt.js';
import { assertAcceptedSdJwtVcTypIfPresent } from './typ.js';

/** `verifySdJwt` の入力オプション。 */
export interface VerifySdJwtOptions {
  /** Issuer-signed JWT の署名検証鍵（発行者公開鍵 JWK）。 */
  readonly issuerKey: PublicKeyJwk;
  /** 期待する `vct`（指定時に payload の `vct` と照合する）。 */
  readonly expectedVct?: string;
  /**
   * KB-JWT 検証時に期待する audience（OID4VP の client_id）。未指定なら `aud` を照合しない。
   * `requireKeyBinding: true` では**必須**（未指定・空文字は 3012）。
   */
  readonly audience?: string;
  /**
   * KB-JWT 検証時に期待する nonce（リプレイ対策）。未指定なら `nonce` を照合しない。
   * `requireKeyBinding: true` では**必須**（未指定・空文字は 3012）。
   */
  readonly nonce?: string;
  /**
   * KB-JWT を必須とするか（VP 提示文脈では true。既定 false）。
   *
   * `true` の場合は `audience` / `nonce` の期待値を両方指定する（従来は任意）。
   * 鍵束縛を要求しながら期待値を渡さない呼び出しは
   * KB-JWT の鍵保持しか確認できず、「この提示宛か」の検査にならないため。
   */
  readonly requireKeyBinding?: boolean;
  /**
   * KB-JWT の最大許容経過秒数（`iat` の鮮度上限）。指定時、`now - iat` がこの値を超える KB-JWT を
   * 古い提示として拒否する（リプレイ対策の補助。主たる対策は nonce + aud）。未指定なら iat を
   * 鮮度評価しない。
   */
  readonly maxAgeSeconds?: number;
  /** 現在時刻（エポック秒）。時刻クレーム・`maxAgeSeconds` 評価の基準。テストの決定性のため注入可能。 */
  readonly nowSeconds?: number;
  /**
   * Issuer-signed JWT の `iat` / `exp` / `nbf` 評価で許容するクロックスキュー秒数。既定 = 上限キャップ
   * `CLOCK_SKEW_PROFILE.vc`（120s）。0 以上 120 以下の整数のみ指定でき、
   * それ以外（キャップ超過・負値・非整数・非数値）は `CLOCK_SKEW_OPTION_INVALID`（4015）で拒否する。
   *
   * **KB-JWT へは同じ値がそのまま適用されるわけではない**: KB-JWT の `iat` 評価には
   * `min(指定値, CLOCK_SKEW_PROFILE.kbJwt)`（= 最大 30s）へクランプした値を用いる。より厳しい KB-JWT
   * プロファイルが常に優先されるため、120 を指定しても KB-JWT が 120s まで緩むことはない。
   */
  readonly clockSkewSeconds?: number;
  /** 発行者の Federation Trust Chain。指定時は署名検証後に FC-11 鍵無効化を自動適用。 */
  readonly issuerTrust?: IssuerTrustOption;
}

/** SD-JWT 検証の成功結果。 */
export interface VerifiedSdJwt {
  /** Issuer payload に `_sd` で隠されていたクレームを復元した平文クレーム。 */
  readonly claims: Readonly<Record<string, unknown>>;
  /** Verifiable Credential Type。 */
  readonly vct: string;
  /** Holder 公開鍵バインド（`cnf`、あれば）。 */
  readonly cnf?: ConfirmationClaim;
  /** Token Status List 参照（`status`、あれば）。 */
  readonly status?: StatusReference;
  /** KB-JWT が同梱され検証に成功したか。 */
  readonly keyBindingVerified: boolean;
}

/** Issuer-signed JWT の署名を検証する。署名不一致も alg と鍵種別の不一致も 3010。 */
function assertIssuerSignature(alg: CredentialAlg, decoded: DecodedJws, key: PublicKeyJwk): void {
  if (!verifyWithJwkOrFalse(alg, decoded, key)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
}

/**
 * SD-JWT VC（提示部 + 任意の KB-JWT）を検証する。
 *
 * @param sdJwt 検証対象の SD-JWT 文字列。
 * @param opts Issuer 検証鍵・期待 vct・クロックスキュー・KB-JWT の aud / nonce 等。
 * @returns 復元した平文クレーム・vct・cnf・status・KB 検証結果。
 * @throws `clockSkewSeconds` 不正（`4015`）/ 形式不正（`3010`）/ 受理対象外の `typ`（`3002`。
 *         欠落は受理する）/ `alg=none`（`3011`）/ 署名不一致・vct 不一致・Disclosure 改竄・
 *         重複/同名衝突・未対応 `_sd_alg`・不正 `status` 形状（`3010`）/
 *         未来 `iat` のスキュー超過（`4014`）/ exp 期限切れ（`3024`）・nbf 有効化前（`3025`）・
 *         時刻型不正（`3002`）/ KB-JWT 付与時の Holder Binding 不一致・不正 `cnf` 形状・KB-JWT の
 *         コンパクト JWS 構造不正、および KB 必須時の KB-JWT 欠落と `audience` / `nonce` 未指定
 *         （空文字・非文字列を含む）（`3012`）/ `issuerTrust` 指定時の
 *         鍵無効化該当・発行時刻欠落（`5012`）・不成立チェーン（`5010`）の場合（VericertsError）。
 */
export function verifySdJwt(sdJwt: string, opts: VerifySdJwtOptions): VerifiedSdJwt {
  // オプション検証は署名検証（暗号処理）より前に済ませる（fail fast）。
  // 任意オプションは自身のプロパティに限って読む。継承した `nowSeconds` は
  // **exp 超過の失効済み SD-JWT VC を受理させる**（`assertTimeClaims` が攻撃者の選んだ
  // 「現在時刻」で評価するため）。`clockSkewSeconds` も同様に時刻検証の窓を動かす。
  const skewSeconds = resolveClockSkewSeconds('vc', ownProperty<number>(opts, 'clockSkewSeconds'));
  const issuerNowSeconds = ownProperty<number>(opts, 'nowSeconds');
  // KB-JWT は VC より厳しい 30s プロファイルを常に優先する。
  const kbSkewSeconds = Math.min(skewSeconds, CLOCK_SKEW_PROFILE.kbJwt);
  // `requireKeyBinding: true` は `audience` / `nonce` の期待値を要求する。KB-JWT の
  // 有無に依らない入力の不備なので、`clockSkewSeconds` と同じく暗号処理より前で fail fast する。
  assertBindingExpectationsPresent(opts);
  const parts = parseSdJwt(sdJwt);
  // Issuer-signed JWT の構造不正は SD-JWT 検証失敗（3010）へ正規化する。
  const decoded = decodeCompactJwsOrThrow(parts.issuerJwt, ErrorCodes.SIG_INVALID);
  const alg = assertAlg(decoded.header);
  // `issuerKey` は SD-JWT VC の**署名検証鍵**。型上必須だが、型の無い JS から省略されると
  // プロトタイプ鎖の汚染値が「渡された鍵」に化け、**攻撃者の鍵で Issuer 署名が検証される**
  // （`vc/verify.ts` の `key` と同じクラスの欠陥）。自身のプロパティに限って読み、
  // 鍵が無ければ署名不成立（3010）へ倒す。
  const issuerKey = ownProperty<PublicKeyJwk>(opts, 'issuerKey');
  if (issuerKey === null || typeof issuerKey !== 'object') {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  assertIssuerSignature(alg, decoded, issuerKey);
  // Issuer JWT の署名で真正性を確認してから `typ` を評価する。`typ` は署名対象なので、改竄された JWT は先に 3010 で落ちる。
  // `typ` も own 限定で読む。鎖読みだと `Object.prototype.typ` の汚染下で、**`typ` を持たない
  // SD-JWT が汚染値で判定され**、本モジュールが文書化している「`typ` 欠落は受理する」挙動が
  // 一律 3002 拒否へ変わる（正当な SD-JWT VC が検証不能になる可用性の欠陥）。
  assertAcceptedSdJwtVcTypIfPresent(ownProperty<unknown>(decoded.header, 'typ'));
  const payload = decoded.payload;
  // FC-11: 署名確定後の鍵無効化突合（未指定なら no-op）。詳細は `issuer-key-revocation.ts`。
  // FC-11 の突合キーは署名検証と**同じ読み方**で取得する（読み方が食い違うと突合だけ汚染値になる）。
  assertSigningKeyNotRevoked(
    payload,
    ownProperty<IssuerTrustOption>(opts, 'issuerTrust'),
    'iat',
    issuerKey,
  );

  // payload はデコード済み JSON（外部入力）。プロトタイプ鎖で読むと、`vct` / `cnf` / `status` を
  // **持たない** SD-JWT に汚染値が生え、型ガード・Holder バインド・失効参照が攻撃者の値になる
  // 自身のプロパティに限って読む。
  const vct = ownProperty<unknown>(payload, 'vct');
  if (typeof vct !== 'string') {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  // 同一関数内で読み方を揃える。鎖読みのままだと、`expectedVct` を省略した
  // 正当な検証が汚染値との突合で一律 3010 に落ちる（fail-closed だが可用性を壊す）。
  const expectedVct = ownProperty<string>(opts, 'expectedVct');
  if (expectedVct !== undefined && vct !== expectedVct) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }

  // Issuer JWT の iat/exp/nbf を評価する（JWT-VC と同じ失効判定。フォーマット間 bypass を塞ぐ）。
  assertTimeClaims(payload, issuerNowSeconds ?? Math.floor(Date.now() / 1000), skewSeconds);

  const claims = recoverClaims(payload, parts);
  // 同一プロパティを 1 度だけ own 読みし、`validateCnf` と KB 必須判定の双方で共有する
  // （読み方が食い違うと、片方だけ汚染値で判定して 3012 を投げる不整合が起きる）。
  const requireKeyBinding = ownProperty<boolean>(opts, 'requireKeyBinding') === true;
  const cnf = validateCnf(ownProperty<unknown>(payload, 'cnf'), requireKeyBinding);
  const status = validateStatus(ownProperty<unknown>(payload, 'status'));

  let keyBindingVerified = false;
  // `parseSdJwt` の戻り値は KB-JWT が無いとき `keyBinding` キーを持たないため own 限定で読む。
  const keyBinding = ownProperty<string>(parts, 'keyBinding');
  if (keyBinding !== undefined) {
    // KB-JWT を除いた提示部（末尾 `~` まで）の sd_hash を計算して照合する。
    const withoutKb = sdJwt.slice(0, sdJwt.length - keyBinding.length);
    assertKeyBinding(keyBinding, cnf, computeSdHash(withoutKb), opts, kbSkewSeconds);
    keyBindingVerified = true;
  } else if (requireKeyBinding) {
    throw new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH);
  }

  const result: {
    claims: Record<string, unknown>;
    vct: string;
    cnf?: ConfirmationClaim;
    status?: StatusReference;
    keyBindingVerified: boolean;
  } = { claims, vct, keyBindingVerified };
  if (cnf !== undefined) {
    result.cnf = cnf;
  }
  if (status !== undefined) {
    result.status = status;
  }
  return result;
}

/**
 * SD-JWT 提示部に Key Binding JWT を付与する（VC バイト列と Holder 秘密鍵を同一プロセスで持つ構成）。
 *
 * Holder が `signer`（cnf に対応する鍵）で KB-JWT（`typ:'kb+jwt'`）を署名し、提示部末尾に連結する。
 * KB-JWT payload は `{ nonce, aud, iat, sd_hash }`。`sd_hash` は KB-JWT を除いた提示部
 * （末尾 `~` まで）の SHA-256（base64url）。ヘッダは発行系と同じ `buildJwsHeader` で組み立てるため、
 * `signer.kid` 設定時は `alg` と `typ` の間に `kid` が入る（未設定時のバイト列は従来どおり）。
 *
 * 実体は `createKeyBindingTemplate` + `attachKeyBindingSignature`（`key-binding.ts`）への委譲であり、
 * 分離型 Holder Service 構成（署名前テンプレートを返し Agent Session が署名する）と同一の
 * KB-JWT バイト列を生成する。ここでは署名鍵が `cnf.jwk` と一致するかは検証しない（不一致は
 * `verifySdJwt` 側が `3012` で検出する）。この挙動を維持するため `verifySignature: false` を渡す。
 *
 * @param sdJwt 提示部 SD-JWT（KB-JWT なし、末尾 `~`）。
 * @param signer Holder の署名鍵（`cnf.jwk` に対応）。
 * @param opts nonce / audience / iat。
 * @returns KB-JWT を連結した SD-JWT 文字列。
 * @throws 入力 SD-JWT に既に KB-JWT が含まれる場合（VericertsError、code `3010`）、`nonce` /
 *         `audience` が空・未対応 alg の場合（code `3012`）。
 */
export function addKeyBinding(
  sdJwt: string,
  signer: CredentialSigner,
  opts: KeyBindingOptions,
): string {
  // `kid` は未設定なら渡さない（`KeyBindingTemplateOptions.kid` は任意プロパティのため）。
  // 判定は `buildJwsHeader` と同じく `Object.hasOwn` に揃える。`signer.kid !== undefined` だと
  // プロトタイプ鎖を辿るため、`Object.prototype.kid` が汚染された環境では **`kid` を持たない
  // signer が署名した KB-JWT のヘッダに攻撃者が選んだ鍵 ID が載る**（検証側の鍵解決を誤導できる）。
  const kid = Object.hasOwn(signer, 'kid') ? signer.kid : undefined;
  const template = createKeyBindingTemplate(sdJwt, {
    ...opts,
    alg: signer.alg,
    ...(kid !== undefined ? { kid } : {}),
  });
  const signature = signer.sign(new TextEncoder().encode(template.signingInput));
  return attachKeyBindingSignature(template, signature, { verifySignature: false });
}
