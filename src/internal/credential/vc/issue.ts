/**
 * JWT-VC（JWS）として W3C VC を発行する最小プリミティブ。
 *
 * VC を JWT-VC payload（`iss` / `sub` / `nbf` / `exp` / `jti` / `vc` の標準 JWT-VC クレーム）に
 * マッピングし、signing-input（`base64url(header).base64url(payload)`）を `CredentialSigner` に
 * 署名させてコンパクト JWS（`header.payload.signature`）を組み立てる。`jose` は使わない。
 * 署名鍵そのもの（privateKey）は本モジュールに渡さず、`signer.ts` の `CredentialSigner` で DI する。
 *
 * KMS / HSM のような非同期署名にも対応するため、`issueCredentialAsync` を併せて提供する。
 * payload マッピングと signing-input の組み立ては同期版と共有し、署名の await 有無のみが異なる。
 *
 * spec: W3C VC Data Model v2.0「JWT-VC」表現。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・VC 本文を含めない。
 * - 発行時の GDPR Art.9 ガードを署名直前に適用する（`10607`）。全 JWT-VC 発行経路が
 *   本モジュールを通るため、ここが SDK の発行系に対する単一の関門になる。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isEpochSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { assertNoSpecialCategoryInIssuedContent } from '../../special-category.js';
import { assembleCompactJws, buildCompactJwsSigningInputFromPayloadJson } from './compact-jws.js';
import { headerSourceWithDidKeyKid } from './did-key-kid.js';
import type { CredentialSignerAlg } from './jws.js';
import { isoToNumericDate } from './numeric-date.js';
import { type AnyCredentialSigner, buildJwsHeader, type CredentialSigner } from './signer.js';
import type { VerifiableCredential } from './vc.js';

/** `issueCredential` / `issueCredentialAsync` の発行オプション。 */
export interface IssueCredentialOptions {
  /**
   * `iat`（発行時刻）に用いるエポック秒。既定は発行時の現在時刻。テストの決定性のため注入可能。
   *
   * `iat` は「JWT を組み立てた実時刻」であり `vc.issuanceDate`（= `nbf`）とは別物である。
   * 未来日付の VC（`issuanceDate` が未来）でも `iat` は実際の発行時刻を指すため、検証側は
   * 「まだ有効化前」（`3025`）と「発行端末の時計が進んでいる」（`4014`）を区別できる。
   */
  readonly nowSeconds?: number;
}

/**
 * VC を JWT-VC payload へマッピングし、signing-input を組み立てる（同期版 / 非同期版で共有）。
 *
 * header は `{ alg, kid?, typ: 'JWT' }`、payload は `iss` / `sub` / `nbf` / `iat` / `exp` / `jti` / `vc`。
 *
 * `iat` は発行時刻（既定は現在時刻。`opts.nowSeconds` で注入可能）で、`nbf` = `vc.issuanceDate` とは
 * 独立に出力する。`iat` は `nbf` ↔ `vc.issuanceDate` の束縛（`assertEnvelopeBinding`）には関与しない。
 *
 * VC 本体と `opts` はいずれも純データなので、読み取りは**関数単位で** own 限定に揃える
 * プロトタイプ鎖で読むと、当該フィールドを**持たない** VC でも
 * `Object.prototype` の汚染値が **署名済み JWT の登録クレーム**（`iss` / `nbf` / `iat` / `exp` /
 * `jti` / `sub`）に載る。本関数は全発行経路（`Wallet.issueCredential`・Issuer モジュール等）
 * の共通基盤であり、ここが鎖読みのままだと上流モジュールの own 化がそのまま無効化される
 * （例: 上流が `vc.id` を own 化しても `jti` には汚染値が載る）。
 *
 * own 読みで取得できなかった**必須**フィールド（`issuer` / `credentialSubject` / `issuanceDate`）は
 * 例外なく発行前に `3002` へ倒す（fail-closed）。ここを欄ごとに non-uniform にすると、`iss` を
 * 落として署名する・`sub` を省いて署名する・`ownProperty(null, 'id')` が生 `TypeError` を投げて
 * `VericertsError` に正規化されない、といった形で**検証側が必ず弾く JWT に署名鍵を使う**ことになる。
 *
 * @param vc 発行する W3C VC。
 * @param signer JWT-VC 署名鍵（`alg` / `kid` を header に反映する）。
 * @param opts `iat` の基準時刻（省略時は現在時刻）。
 * @returns signing-input（`base64url(header).base64url(payload)`）。
 * @throws issuer / credentialSubject / issuanceDate が未指定・型不正の場合、
 *         issuanceDate / expirationDate が解釈不能な場合（VericertsError、code `3002`）、
 *         payload が Art.9 特別カテゴリ属性を含む場合（code `10607`）。
 */
function buildSigningInput(
  vc: VerifiableCredential,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
  opts: IssueCredentialOptions,
): string {
  // `iss` は署名対象の発行者クレーム。取得できない VC をそのまま署名すると `iss` の無い JWT-VC が
  // できあがり、検証側（`assertVerifiableCredential` / `extractAndAssert`）が必ず 3002 で弾く。
  // 「検証不能な JWT に署名鍵を使う」ことになるため、`issuanceDate` と同じく発行前に倒す。
  const issuer = ownProperty<string>(vc, 'issuer');
  if (typeof issuer !== 'string') {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  // `kid` は signer の明示指定を優先し、無ければ発行者が署名鍵自身の `did:key` のときだけ検証メソッド id
  // を自動で載せる（didkit-http のように `kid` からしか検証鍵を解決しない検証側向け。did-key-kid.ts）。
  const header = buildJwsHeader(headerSourceWithDidKeyKid(issuer, signer), 'JWT');
  // `nbf` は署名対象の時刻クレーム。取得できない VC を `as` で下流へ流すと `Date.parse(undefined)`
  // が NaN になり、JSON 直列化で `null` へ倒れて検証時まで表面化しない。ここで 3002 に倒す。
  const issuanceDate = ownProperty<string>(vc, 'issuanceDate');
  if (typeof issuanceDate !== 'string') {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  // `credentialSubject` とその `id` も own 読みで辿る（途中で鎖読みに戻すと `sub` に汚染値が載る）。
  // クレーム本体は VC の必須欄。欠落・`null` を許すと `ownProperty(null, 'id')` が生の `TypeError`
  // を投げて `VericertsError` へ正規化されないため、ここで型ごと fail-closed に倒す。
  const credentialSubject = ownProperty<Readonly<Record<string, unknown>>>(vc, 'credentialSubject');
  if (typeof credentialSubject !== 'object' || credentialSubject === null) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const iat = ownProperty<number>(opts, 'nowSeconds') ?? Math.floor(Date.now() / 1000);
  // 非有限・負値・文字列の `iat` は JWT に `null` 等で載り、検証側が必ず弾く VC に署名鍵を使う。
  if (!isEpochSeconds(iat)) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const payload: Record<string, unknown> = {
    iss: issuer,
    nbf: isoToNumericDate(issuanceDate),
    iat,
    vc,
  };
  // `credentialSubject.id` は任意（subject を持たない VC もある）。string のときだけ `sub` に載せる。
  const subjectId = ownProperty<unknown>(credentialSubject, 'id');
  if (typeof subjectId === 'string') {
    payload.sub = subjectId;
  }
  const expirationDate = ownProperty<string>(vc, 'expirationDate');
  if (expirationDate !== undefined) {
    payload.exp = isoToNumericDate(expirationDate);
  }
  const vcId = ownProperty<string>(vc, 'id');
  if (vcId !== undefined) {
    payload.jti = vcId;
  }
  // VC 発行時に要配慮個人情報を含むクレームを検査する。
  // 全 JWT-VC 発行経路（`Wallet.issueCredential` / `IssuerModule.issueVC` /
  // Credential Chain）がこの署名プリミティブを通るため、ここに置けば
  // 「渡されたものをそのまま署名する」経路も含めて漏れなく覆え、今後増える発行経路も自動的に覆われる。
  //
  // payload を **一度だけ**直列化し、その文字列を解析した値を走査したうえで**同じ文字列**を
  // base64url する。これにより「検査した値」と「署名バイト列」が定義上一致し、検査と署名の間に
  // payload を読み直す余地がない。したがって own アクセサの二重評価（検査時と署名時で違う値を
  // 返す）も、非列挙 own プロパティのすり抜け（走査されないまま署名される。`JSON.stringify` は
  // 非列挙プロパティを出力しないため、そもそも署名対象に入らない）も原理的に成立しない。
  // `validate-issue-input.ts` のスナップショット方式は「走査対象と VC に載る値が同じ**オブジェクト**」
  // までしか保証しないので、本方式のほうが強い。パースには `parseJsonWithoutPrototype` を使う。
  //
  // 既知の限界: `payload` を組み立てる前に `ownProperty(vc, 'issuer' | 'issuanceDate' | ...)` を
  // 読むため、`vc` 側に getter があると登録済みクレーム用と `vc` 本体の直列化用とで 2 回評価される
  // （既存挙動）。ただし走査対象は直列化後の文字列なので、Art.9 の不変条件は保たれる。
  //
  // ガードは `signer.sign` より前に走るため、拒否時に署名鍵は一切使われない（fail-closed）。
  const payloadJson = JSON.stringify(payload);
  assertNoSpecialCategoryInIssuedContent(parseJsonWithoutPrototype(payloadJson));
  return buildCompactJwsSigningInputFromPayloadJson(header, payloadJson);
}

/**
 * VC を JWT-VC（コンパクト JWS）として発行する。
 *
 * header は `{ alg, typ: 'JWT' }`（`signer.kid` 設定時は `alg` と `typ` の間に `kid` を挿入）、
 * payload は以下の標準 JWT-VC クレームに VC をマッピングする:
 * - `iss` = `vc.issuer`（発行者 DID）
 * - `sub` = `vc.credentialSubject.id`（存在すれば。subject DID）
 * - `nbf` = `vc.issuanceDate` の NumericDate
 * - `iat` = 発行時刻の NumericDate（既定は現在時刻。`opts.nowSeconds` で注入可能）
 * - `exp` = `vc.expirationDate` の NumericDate（存在すれば）
 * - `jti` = `vc.id`（存在すれば）
 * - `vc`  = VC 本体
 *
 * 署名鍵は `CredentialSigner`（`signer.ts`）で DI する。生 privateKey を本関数に渡さないことで、
 * keymanager のように鍵を非公開のまま保持する実装からも privateKey を露出せず発行できる。
 * 生 privateKey から発行する場合は `createPrivateKeySigner` で signer を生成して渡す。
 *
 * @param vc 発行する W3C VC。
 * @param signer JWT-VC 署名鍵（alg / publicKeyJwk / sign を提供）。
 * @param opts `iat` の基準時刻（省略時は現在時刻）。
 * @returns コンパクト JWT-VC 文字列（`header.payload.signature`）。
 * @throws 必須欄（`issuer` / `credentialSubject` / `issuanceDate`）を自身のプロパティとして
 *         持たない・型不正の場合、issuanceDate / expirationDate が解釈不能な場合
 *         （VericertsError、code `3002`）、VC が Art.9 特別カテゴリ属性を含む場合（code `10607`）、
 *         signer による署名演算が失敗した場合（code `1020`）。
 *         signer 構築時の鍵不正（`1003` 等）は呼び出し側（`createPrivateKeySigner` /
 *         `getCredentialSigner`）で発生する。
 */
export function issueCredential(
  vc: VerifiableCredential,
  signer: CredentialSigner<CredentialSignerAlg>,
  opts: IssueCredentialOptions = {},
): string {
  // signing-input（`base64url(header).base64url(payload)`）を組み立て、signer に署名させる。
  // signer は signing-input の SHA-256 を取って 64B raw(r||s) を返す責務を持つ。
  const signingInput = buildSigningInput(vc, signer, opts);
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return assembleCompactJws(signingInput, signature);
}

/**
 * VC を JWT-VC（コンパクト JWS）として発行する（非同期署名対応版）。
 *
 * header / payload のマッピングは `issueCredential` と完全に同一で、署名だけを `await` する。
 * 同期の local signer（`createPrivateKeySigner`）と非同期の Remote Signer
 * （`createRemoteSigner`。KMS / HSM）のどちらも受け付けるため、`AnyCredentialSigner` を取る。
 * 同期 signer と同一の `opts.nowSeconds` を渡した場合の出力は `issueCredential` とバイト単位で
 * 一致する（後方互換）。`nowSeconds` 未指定時は双方が各自の現在時刻を読むため `iat` だけが異なりうる。
 *
 * @param vc 発行する W3C VC。
 * @param signer JWT-VC 署名鍵（同期 `CredentialSigner` / 非同期 `AsyncCredentialSigner`）。
 * @param opts `iat` の基準時刻（省略時は現在時刻）。
 * @returns コンパクト JWT-VC 文字列（`header.payload.signature`）の Promise。
 * @throws 必須欄（`issuer` / `credentialSubject` / `issuanceDate`）を自身のプロパティとして
 *         持たない・型不正の場合、issuanceDate / expirationDate が解釈不能な場合
 *         （VericertsError、code `3002`）、VC が Art.9 特別カテゴリ属性を含む場合（code `10607`）、
 *         signer による署名演算・外部署名呼び出しが失敗した場合（code `1020`）。
 */
export async function issueCredentialAsync(
  vc: VerifiableCredential,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
  opts: IssueCredentialOptions = {},
): Promise<string> {
  const signingInput = buildSigningInput(vc, signer, opts);
  const signature = await signer.sign(new TextEncoder().encode(signingInput));
  return assembleCompactJws(signingInput, signature);
}
