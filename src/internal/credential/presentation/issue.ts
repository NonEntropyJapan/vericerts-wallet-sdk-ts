/**
 * JWT-VP（JWS）として W3C VP を署名する最小プリミティブ。
 *
 * `issueCredential`（`vc/issue.ts`）と対をなす VP 版。VP を JWT-VP payload（`iss` = holder /
 * `aud` = verifier / `nonce` / `iat` / `exp` / `jti` / `vp`）にマッピングし、`CredentialSigner` で署名して
 * コンパクト JWS を組み立てる。`jose` は使わない。検証は `presentation.ts` が担う。
 *
 * KMS / HSM のような非同期署名にも対応するため `issuePresentationAsync` を併せて提供する
 * payload マッピングと signing-input の組み立ては同期版と共有し、署名の `await`
 * 有無のみが異なる。
 *
 * SDK の JWT-VP 形式では、W3C VC Data Model v2.0 の VP を JWT ペイロードの `vp` クレームに格納する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・VC 本文・開示値・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isEpochSeconds, isLifetimeSeconds } from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { assembleCompactJws, buildCompactJwsSigningInput } from '../vc/compact-jws.js';
import type { CredentialSignerAlg } from '../vc/jws.js';
import { type AnyCredentialSigner, buildJwsHeader, type CredentialSigner } from '../vc/signer.js';
import { assertVerifiablePresentation, type VerifiablePresentation } from './vp.js';

/** `issuePresentation` の発行オプション（OID4VP の verifier バインド）。 */
export interface IssuePresentationOptions {
  /** Verifier 識別子（OID4VP の audience）。指定時は payload の `aud` に設定する。 */
  readonly audience?: string;
  /** Verifier 発行の nonce（リプレイ対策）。指定時は payload の `nonce` に設定する。 */
  readonly nonce?: string;
  /**
   * VP の有効期間（秒）。指定時は payload の `exp`（NumericDate）を `基準時刻 + expiresInSeconds`
   * に設定する。検証側（`verifyPresentation`）が期限切れを `VC_EXPIRED`（3024）で拒否する。
   */
  readonly expiresInSeconds?: number;
  /**
   * 発行時刻（エポック秒）。テストの決定性のため注入可能。既定は現在時刻。
   * payload の `iat` に設定し、`expiresInSeconds` 指定時は `exp` の基準時刻としても用いる。
   */
  readonly nowSeconds?: number;
}

/**
 * VP を JWT-VP payload へマッピングし、signing-input を組み立てる（同期版 / 非同期版で共有）。
 *
 * 発行前に VP 構造を検証する（不正な VP を署名しない）。
 *
 * @param vp 署名する W3C VP。
 * @param signer JWT-VP 署名鍵（`alg` / `kid` を header に反映する）。
 * @param opts audience / nonce / exp / 発行時刻。
 * @returns signing-input（`base64url(header).base64url(payload)`）。
 * @throws VP 構造不正の場合（VericertsError、code `3002`）。
 */
function buildPresentationSigningInput(
  vp: VerifiablePresentation,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
  opts: IssuePresentationOptions,
): string {
  assertVerifiablePresentation(vp);
  const header = buildJwsHeader(signer, 'JWT');
  // 任意プロパティは自身のプロパティに限って読む。ここで組み立てた payload は
  // そのまま署名されるため、継承値を拾うと、その項目を**省略した**正当な発行でも汚染値が
  // **署名済み JWT-VP** に載る:
  // - `audience`: 意図しない Verifier 向けの `aud` が付き、その Verifier で VP が受理される。
  // - `nonce`: 攻撃者の選んだ nonce が載り、リプレイ対策のバインドが攻撃者側の値になる。
  // - `nowSeconds` / `expiresInSeconds`: `iat` / `exp` が攻撃者の選んだ有効期間になる
  //   （実質無期限の VP）。
  const audience = ownProperty<string>(opts, 'audience');
  const nonce = ownProperty<string>(opts, 'nonce');
  const expiresInSeconds = ownProperty<number>(opts, 'expiresInSeconds');
  // `iat` と `exp` は同一の基準時刻から導く（両者が別々の現在時刻を読むと有効期間がずれるため）。
  const issuedAt = ownProperty<number>(opts, 'nowSeconds') ?? Math.floor(Date.now() / 1000);
  // 非有限・負値・文字列は JWT に `null` 等で載り、検証側が必ず弾く VP に署名鍵を使うことになる。
  if (
    !isEpochSeconds(issuedAt) ||
    (expiresInSeconds !== undefined && !isLifetimeSeconds(issuedAt, expiresInSeconds))
  ) {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const payload: Record<string, unknown> = {
    iss: vp.holder,
    iat: issuedAt,
    vp,
  };
  if (audience !== undefined) {
    payload.aud = audience;
  }
  if (nonce !== undefined) {
    payload.nonce = nonce;
  }
  if (expiresInSeconds !== undefined) {
    payload.exp = issuedAt + expiresInSeconds;
  }
  // `vp.id` は VP 本文（データ）。継承値を拾うと、`id` を持たない VP にも `jti` が載る。
  const vpId = ownProperty<string>(vp, 'id');
  if (vpId !== undefined) {
    payload.jti = vpId;
  }
  return buildCompactJwsSigningInput(header, payload);
}

/**
 * VP を JWT-VP（コンパクト JWS）として署名する。
 *
 * header は `buildJwsHeader(signer, 'JWT')`（`signer.kid` 設定時は `alg` と `typ` の間に `kid` を
 * 挿入する）、payload は以下にマッピングする:
 * - `iss`   = `vp.holder`（提示者 DID）
 * - `aud`   = `opts.audience`（存在すれば。Verifier 識別子）
 * - `nonce` = `opts.nonce`（存在すれば。リプレイ対策）
 * - `iat`   = 発行時刻（既定は現在時刻。`opts.nowSeconds` で注入可能）
 * - `exp`   = `基準時刻 + opts.expiresInSeconds`（`expiresInSeconds` 指定時。VP の有効期限）
 * - `jti`   = `vp.id`（存在すれば）
 * - `vp`    = VP 本体
 *
 * 署名鍵は `CredentialSigner`（`signer.ts`）で DI する（生 privateKey を本関数に渡さない）。
 * KMS / HSM のような非同期署名が必要な場合は `issuePresentationAsync` を用いる。
 *
 * @param vp 署名する W3C VP。
 * @param signer JWT-VP 署名鍵（holder の鍵）。
 * @param opts audience / nonce（OID4VP）・有効期間・発行時刻。
 * @returns コンパクト JWT-VP 文字列（`header.payload.signature`）。
 * @throws VP 構造不正の場合（VericertsError、code `3002`）、署名演算失敗の場合（code `1020`）。
 */
export function issuePresentation(
  vp: VerifiablePresentation,
  signer: CredentialSigner<CredentialSignerAlg>,
  opts: IssuePresentationOptions = {},
): string {
  const signingInput = buildPresentationSigningInput(vp, signer, opts);
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  return assembleCompactJws(signingInput, signature);
}

/**
 * VP を JWT-VP（コンパクト JWS）として署名する（非同期署名対応版）。
 *
 * header / payload のマッピングは `issuePresentation` と完全に同一で、署名だけを `await` する。
 * 同期の local signer（`createPrivateKeySigner`）と非同期の Remote Signer（`createRemoteSigner`。
 * KMS / HSM）のどちらも受け付けるため `AnyCredentialSigner` を取る。同期 signer を渡した場合の
 * 出力は `issuePresentation` とバイト単位で一致する（後方互換）。
 *
 * @param vp 署名する W3C VP。
 * @param signer JWT-VP 署名鍵（同期 `CredentialSigner` / 非同期 `AsyncCredentialSigner`）。
 * @param opts audience / nonce（OID4VP）・有効期間・発行時刻。
 * @returns コンパクト JWT-VP 文字列（`header.payload.signature`）の Promise。
 * @throws VP 構造不正の場合（VericertsError、code `3002`）、署名演算・外部署名呼び出しが
 *         失敗した場合（code `1020`）。
 */
export async function issuePresentationAsync(
  vp: VerifiablePresentation,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
  opts: IssuePresentationOptions = {},
): Promise<string> {
  const signingInput = buildPresentationSigningInput(vp, signer, opts);
  const signature = await signer.sign(new TextEncoder().encode(signingInput));
  return assembleCompactJws(signingInput, signature);
}
