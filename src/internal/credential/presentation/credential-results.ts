/**
 * VP に内包された VC（`vp.verifiableCredential`）の検証と `credentialResults` の組み立て。
 *
 * VP 署名の検証に加え、含まれるすべての VC を検証し、個々の結果を `credentialResults` に返す。
 *
 * **検証鍵を DI する理由**: `verifyPresentation` は holder DID の解決を責務外とし VP 署名鍵を
 * `opts.key` で DI する。内包 VC の**発行者**鍵解決も同じ理由で本 API の責務外であり、
 * `opts.credentialKey` で解決する。`verifyCredentialChainOnPresentation` の `extractVcId` と同じ
 * 設計で、DID 解決を持つ上位（Wallet ファサード）が配線する。
 *
 * **fail-closed**: 「検証できなかった VC」は成功にしない。`credentialKey` 未指定・鍵解決不能・
 * 未対応フォーマット（Data Integrity proof の JSON-LD VC）はいずれも `valid: false` で返す。ただし
 * **例外は投げない**（戻り値が `valid` / `errors?` を持つ結果オブジェクト形であり、1 件でも
 * 例外にすると残りの VC の結果を返せなくなるため）。したがって**呼び出し側は `valid` を必ず確認
 * する**こと。`presentation` だけを読むと未検証の VC を受理してしまう。
 *
 * `issuerTrust` は内包 VC の検証へ中継し、発行者鍵の無効化宣言を VP 経由でも適用する。
 *
 * セキュリティ上の注意:
 * - `errors` にはエラーコードだけを入れ、VC 本文・開示値・JWT を含めない。
 */

import { type ErrorCode, ErrorCodes } from '../../errors.js';
import type { PresentationWorkBudget } from '../../primitives/presentation-work-budget.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import type { TrustedIssuerList } from '../../trusted-issuer/types.js';
import type { VCFormat } from '../format-negotiation/types.js';
import type { IssuerTrustOption } from '../issuer-key-revocation.js';
import type { CredentialVerifierKey } from '../vc/verify.js';
import { verifyAllEmbeddedEntries } from './credential-entry/verify-all.js';
import type { AssertedVerifiablePresentation } from './vp.js';

/** VP の `verifiableCredential` 要素（JWT-VC / SD-JWT VC 文字列、または JSON-LD VC object）。 */
export type EmbeddedCredentialEntry = string | Readonly<Record<string, unknown>>;

/** `credentialKey` コールバックへ渡す検証対象の識別情報。 */
export interface EmbeddedCredentialKeyRequest {
  /** `verifiableCredential` の要素そのもの。 */
  readonly entry: EmbeddedCredentialEntry;
  /** `verifiableCredential` 内での位置（0 起点）。 */
  readonly index: number;
  /** 判別したフォーマット。 */
  readonly format: VCFormat;
  /** 取り出せた発行者 DID（`iss`）。取り出せなかった場合は空文字列。 */
  readonly issuerDID: string;
}

/**
 * 内包 VC の発行者検証鍵を返す DI コールバック。
 *
 * 鍵を用意できない要素には `undefined` を返す（その VC は `valid: false` になる）。SD-JWT VC は
 * `verifySdJwt` が JWK しか受け取らないため、`{ verify }` 形式の鍵を返しても検証できない
 * （`3010` で fail-closed になる）。
 */
export type EmbeddedCredentialKeyResolver = (
  request: EmbeddedCredentialKeyRequest,
) => CredentialVerifierKey | undefined;

/** 内包 VC 1 件の検証結果。 */
export interface VerificationResult {
  /** 署名・時刻・（指定時）FC-11 をすべて通ったか。 */
  readonly valid: boolean;
  /** 失敗理由のエラーコード（`ErrorCodes` の値）。成功時は持たない。 */
  readonly errors?: readonly ErrorCode[];
  /** 発行者 DID（`iss`）。取り出せなかった場合は空文字列。 */
  readonly issuerDID: string;
  /** `exp` が現在時刻より過去か（`exp` を持たない VC は `false`）。 */
  readonly isExpired: boolean;
  // isRevoked / isSuspended / schemaValid の 3 つは失効 / 一時停止 / スキーマの各チェック結果。
  // 本経路はいずれも実行しないため、spec の「未実行」を表す `null` を常に返す（`false` にすると
  // 「検査して問題なし」と誤読される）。
  readonly isRevoked: boolean | null;
  readonly isSuspended: boolean | null;
  /**
   * Trusted Issuer List（TIL）照合の結果。
   *
   * `verifyPresentation` に `trustedIssuerList` が DI されていない、または `issuerDID` を
   * 取り出せなかった場合は「未実行」を表す `null` を返す（`false` にすると「照合して信頼済み
   * ではなかった」と誤読される）。DI された場合は `isTrustedIssuer(list, issuerDID)` の結果。
   */
  readonly isTrustedIssuer: boolean | null;
  readonly schemaValid: boolean | null;
  /** 判別したフォーマット。 */
  readonly format: VCFormat;
}

/**
 * `VerifiedPresentation` のうち、内包 VC 検証が決めるフィールド。
 *
 * `VerifiedPresentation` がこれを継承する形で公開する（`header` / `payload` / `presentation` は
 * 従来どおり返す。既存の呼び出し側は影響を受けない）。
 */
export interface PresentationVerificationFields {
  /**
   * VP 署名**かつ**全内包 VC が有効か。内包 VC の失敗は例外にならないため必ず確認すること。
   *
   * **内包 VC が 1 件も無い VP は `valid: false`**（`errors` に `3002`）。空集合に対する `every` の
   * 空真で「何も証明しない提示」が通るのを塞ぐ。
   *
   * **保証しない範囲**: 既定（`requireHolderBinding` 未指定 / `false`）では、`valid` は「VP 署名が
   * 正当」かつ「各内包 VC の発行者署名・時刻・（指定時）FC-11 が正当」を意味するに過ぎず、**内包 VC
   * が提示者（`vp.holder`）のものであることは検証していない**。JWT-VC 経路は VC の `sub` と `holder`
   * を突き合わせず、SD-JWT VC 経路は `requireKeyBinding` を渡さない。したがって**第三者に正当に発行
   * された VC を攻撃者が自分の VP に詰めても `valid: true` になる**。所有者性が要る用途では
   * `requireHolderBinding: true` を指定すること。
   */
  readonly valid: boolean;
  /** 提示者 DID（`vp.holder` = JWT の `iss`）。 */
  readonly holderDID: string;
  /** 内包 VC の失敗理由コードを重複なく集めたもの。すべて有効なら持たない。 */
  readonly errors?: readonly ErrorCode[];
  /** 各内包 VC の検証結果（`vp.verifiableCredential` と同じ順序・同じ長さ）。 */
  readonly credentialResults: readonly VerificationResult[];
}

/**
 * 内包 VC 検証に必要な入力（`verifyPresentation` のオプションから抽出済み）。
 *
 * `credentialKey` / `issuerTrust` は**任意プロパティにせず、未指定でも `undefined` を明示的に
 * 持たせる**（`?:` ではなく `| undefined`）。省略可能にすると本オブジェクトが当該キーを own
 * プロパティとして持たない状態が生まれ、読み取りが `Object.prototype` の汚染値を拾う。つまり
 * 呼び出し側が DI を**渡していない**のに汚染コールバックが鍵解決に採用され、fail-closed のはずの
 * 経路が「攻撃者の鍵で検証済み」に化ける。own で shadow して塞ぐ。
 *
 * ただし**型はこの門にならない**。`verifyEmbeddedCredentials` は公開プリミティブであり、公開
 * ESM / CJS を使う JS 消費者はどのキーでも省略できる。そのため `credentialKey` / `holderDID` は
 * **使用地点でも**汚染を弾いており（`credential-entry/holder-binding.ts`）、この 2 つは
 * キーを省略しても fail-closed に倒れる。
 */
export interface EmbeddedCredentialVerifyInput {
  /** 発行者鍵の DI コールバック（`undefined` なら全件 fail-closed）。 */
  readonly credentialKey: EmbeddedCredentialKeyResolver | undefined;
  /** FC-11 の Trust Chain。内包 VC の検証へそのまま中継する。 */
  readonly issuerTrust: IssuerTrustOption | undefined;
  /** 時刻評価の基準（エポック秒）。 */
  readonly nowSeconds: number;
  /**
   * 内包 VC の時刻評価で許容するクロックスキュー秒数（`undefined` なら VC 既定の 120s）。
   *
   * `verifyPresentation` に渡された値をそのまま中継する。中継しないと、VP 側で
   * `clockSkewSeconds: 0` と厳格化した呼び出しでも内包 VC だけ既定 120 秒で評価され、
   * **失効直後の内包 VC が `valid: true` / `isExpired: false` で通る**（指定が黙って無視される）。
   * VP のキャップは 30s・VC は 120s なので、VP 側で受理された値は VC 側でも必ず値域内に収まる。
   */
  readonly clockSkewSeconds: number | undefined;
  /**
   * 提示者 DID（`vp.holder`）。`requireHolderBinding: true` のとき JWT-VC の `sub` と突き合わせる
   * `requireHolderBinding` が `false` なら参照されない。
   */
  readonly holderDID: string;
  /**
   * 内包 VC が提示者のものであることを要求するか。
   *
   * `false`（既定）なら従来どおり発行者署名・時刻・FC-11 までしか見ない。`true` なら JWT-VC は
   * `sub === holderDID`（`sub` 欠落の bearer VC は拒否）、SD-JWT VC は `requireKeyBinding: true`
   * での `cnf` + KB-JWT 検証を要求する。
   *
   * **`true` のときは `audience` / `nonce` の両方が必須（fail-closed）。** どちらかが `undefined`
   * なら内包 SD-JWT VC は KB-JWT の内容によらず `3012` で `valid: false` になる。
   */
  readonly requireHolderBinding: boolean;
  /**
   * SD-JWT VC の KB-JWT 検証へ中継する**実効** audience（OID4VP の `aud`）。
   *
   * `requireHolderBinding: false`（既定）なら未指定時は照合しない。**`true` のときの `undefined`
   * は「照合しない」ではなく `3012`** で、KB-JWT の内容によらず当該 VC が `valid: false` になる
   * （fail-closed。`nonce` も同様で、両方揃っていることが突合の前提）。
   *
   * 中継しないと、`cnf` を持つ内包 SD-JWT VC に付いた KB-JWT が別の Verifier / 別セッション宛でも
   * 素通りする（配線漏れ）。呼び出し側が検証済みの値だけを渡すこと（replay 検知
   * 経路では `nonceContext` の束縛値と照合済みの実測 `aud`）。
   */
  readonly audience: string | undefined;
  /**
   * SD-JWT VC の KB-JWT 検証へ中継する**実効** nonce。`audience` と同趣旨で、fail-closed の扱いも
   * 同じ（`requireHolderBinding: true` のときの `undefined` は「照合しない」ではなく `3012`）。
   */
  readonly nonce: string | undefined;
  /**
   * Trusted Issuer List。
   *
   * DI された場合のみ、各内包 VC の `issuerDID` を `isTrustedIssuer(list, issuerDID)` で照合し
   * `VerificationResult.isTrustedIssuer` に反映する。**`undefined`（既定）なら従来どおり
   * 照合を行わず `null`（未実行）を返す**（opt-in。`credentialKey` / `issuerTrust` と同じ
   * DI パターン）。
   */
  readonly trustedIssuerList: TrustedIssuerList | undefined;
  /**
   * VP 1 通で共有する仕事量の残予算（署名検証・信頼リスト走査）。省略時は VP 専用に作る。
   * `verifyCredentialChainOnPresentation` / type metadata 解決へ同じものを渡すと VP 全体で消費する。
   */
  readonly workBudget?: PresentationWorkBudget;
}

/**
 * VP に内包された全 VC を検証し、`credentialResults` を組み立てる。
 *
 * 要素の並び順は `vp.verifiableCredential` と 1 対 1 に対応する（スキップしない）。要素数
 * （`MAX_PRESENTATION_CREDENTIALS`）と仕事量の共有予算の超過は例外（`3002`）で VP 全体を拒否する。
 *
 * @param entries VP の `verifiableCredential`。
 * @param input 発行者鍵の DI・FC-11 の Trust Chain・現在時刻・クロックスキュー。
 * @returns 各 VC の検証結果（入力と同じ長さ・同じ順序）。
 */
export function verifyEmbeddedCredentials(
  entries: ReadonlyArray<EmbeddedCredentialEntry>,
  input: EmbeddedCredentialVerifyInput,
): VerificationResult[] {
  return verifyAllEmbeddedEntries(entries, input);
}

/**
 * 内包 VC の検証結果から `PresentationVerificationFields` を組み立てる。
 *
 * `valid` は「**内包 VC が 1 件以上あり**、かつ全件が有効」で決まる（VP 署名の失敗は呼び出し元が
 * 例外として先に投げるため、ここへ到達した時点で VP 署名は検証済み）。`errors` は内包 VC の失敗
 * コードを重複なく集める。
 *
 * **空の `verifiableCredential` を `valid: true` にしない**。`every([])` は空真なので
 * 素朴に書くと、envelope 署名・`aud` / `nonce` 束縛・時刻クレームを満たした**内包 VC ゼロの holder
 * 署名済み VP** が `valid: true` かつ `errors` 省略で返り、契約どおり `valid` だけを見る RP が
 * 「提示者がある DID を保有している」以外を何も証明しない提示で認可してしまう。`valid: true` は
 * 「envelope 正当 **かつ** 全内包 VC が有効」という連言であり、空集合でこれを空虚に成立させない。
 * 理由コードは `3002`（提示すべき VC を 1 件も含まない VP 構造）で返し、異常のシグナルを必ず残す。
 */
function buildPresentationVerificationFields(
  holderDID: string,
  credentialResults: readonly VerificationResult[],
): PresentationVerificationFields {
  if (credentialResults.length === 0) {
    return {
      valid: false,
      holderDID,
      credentialResults,
      errors: [ErrorCodes.VC_SCHEMA_INVALID],
    };
  }
  const errors = [...new Set(credentialResults.flatMap((result) => result.errors ?? []))];
  return {
    valid: credentialResults.every((result) => result.valid),
    holderDID,
    credentialResults,
    ...(errors.length > 0 ? { errors } : {}),
  };
}

/**
 * `verifyPresentation` のオプションから内包 VC 検証の入力を取り出し、結果フィールドを組み立てる。
 *
 * `credentialKey` は**関数値**なので own 限定では読まない（`class Deps { credentialKey() {} }` の
 * ようにプロトタイプメソッドで実装した DI が無言で「未指定」になり、全 VC が検証不能に落ちる）。
 * `Object.prototype` 由来だけを弾き、関数でない値は未指定として扱う。継承値を採用すると、
 * コールバックを**渡していない**呼び出しで鍵解決が攻撃者の関数へ委譲され「検証済み」に化ける。
 * 純データの `issuerTrust` / `clockSkewSeconds` / `requireHolderBinding` / `expectedAudience` /
 * `expectedNonce` は own 限定で読む（継承値は FC-11 の突合材料を攻撃者制御にし、スキューは時刻検証の
 * 窓を呼び出し側の意図より広げ、`expected*` の汚染値は KB-JWT を攻撃者が選んだ相手・セッションへ
 * 束縛したことにする）。
 *
 * @param checked `assertVerifiablePresentationMembers` が構造検証した VP と、その検証に使った
 *                own メンバ。本関数は `holder` / `verifiableCredential` をここから直接使う。
 * @param opts `verifyPresentation` に渡されたオプション（生のまま。読み方は本関数が決める）。
 * @param nowSeconds 時刻評価の基準（VP 署名検証と同じ値）。
 * @returns `valid` / `holderDID` / `credentialResults`（失敗があれば `errors`）。
 */
export function resolvePresentationVerificationFields(
  checked: AssertedVerifiablePresentation,
  opts: object,
  nowSeconds: number,
): PresentationVerificationFields {
  const credentialKey = nonObjectPrototypeProperty<EmbeddedCredentialKeyResolver>(
    opts,
    'credentialKey',
  );
  // メンバは `assertVerifiablePresentationMembers` が**一度だけ**読んだ値を `checked` として
  // 受け取る。本関数は VP オブジェクト（`checked.vp`）を読み直さない。読み直すと、own アクセサ
  // 付きの VP を渡された場合に 2 度目が別の値を返し、**内包 VC の Holder Binding 突合に使った
  // DID と、返り値 `holderDID` として報告する DID が食い違う**（TOCTOU）。
  const holder = checked.holder;
  const embedded = checked.verifiableCredential;
  const results = verifyEmbeddedCredentials(embedded, {
    // キーは常に生やす（条件付き展開で落とすと下流の読み取りが継承値を拾う。上の JSDoc 参照）。
    credentialKey: typeof credentialKey === 'function' ? credentialKey : undefined,
    issuerTrust: ownProperty<IssuerTrustOption>(opts, 'issuerTrust'),
    clockSkewSeconds: ownProperty<number>(opts, 'clockSkewSeconds'),
    nowSeconds,
    holderDID: holder,
    // `=== true` で正規化する。`Object.prototype.requireHolderBinding` の汚染は own 読みで
    // 弾かれるので、渡していない呼び出しが黙って厳格化されることはない。
    requireHolderBinding: ownProperty<boolean>(opts, 'requireHolderBinding') === true,
    // KB-JWT へ中継するのは**検証済みの期待値**だけ（payload の実測 `aud` / `nonce` ではない）。
    // 既定（束縛）モードでは両者が一致していることを `assertVpClaims` が既に確認している。
    audience: ownProperty<string>(opts, 'expectedAudience'),
    nonce: ownProperty<string>(opts, 'expectedNonce'),
    // Trusted Issuer List も own 限定で読む。継承値を拾うと、list を**渡していない**
    // 呼び出しが `Object.prototype` 汚染値を「呼び出し側が渡した信頼リスト」として採用し、
    // 未指定のはずの照合が攻撃者制御のリストで実行されてしまう（issuerTrust と同じ理由）。
    trustedIssuerList: ownProperty<TrustedIssuerList>(opts, 'trustedIssuerList'),
    // 共有の仕事量予算。own 限定で読む（継承値は上限を攻撃者の巨大な値に差し替える）。
    // 渡されなければ `verifyEmbeddedCredentials` が VP 専用に作る。
    workBudget: ownProperty<PresentationWorkBudget>(opts, 'workBudget'),
  });
  return buildPresentationVerificationFields(holder, results);
}
