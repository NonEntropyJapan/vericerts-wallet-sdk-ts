/**
 * VC を含まない VC Data Model 2.0 の VP を `vp+jwt`（JWS）として署名する。
 *
 * `issue.ts` の `issuePresentation` は VP を `{ iss, iat, vp }` に包む JWT-VP（VC DM 1.1 形式・`typ=JWT`）で、
 * VC Data Model 2.0 の JOSE 表現（vc-jose-cose §3.1.2。`typ=vp+jwt`、ペイロードが VP そのもの）とは別物である。
 * 本関数は後者を作る（既存の `issuePresentation` は変えない）。VP は `holder` が自分の鍵で署名したことだけを示し、
 * `verifiableCredential` は持たない（SIOPv2 の anchor ログインが求める「資格を含まない VP」）。
 *
 * ペイロードは VP のクレームそのもの（`@context` / `type` / `holder`）に、OID4VP の verifier バインド
 * （`aud` = verifier の `client_id`、`nonce`）を足したもの。JWT の `vp` / `vc` クレームは持たない
 * （vc-jose-cose §3.1.1: 含めてはならない）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・JWT を含めない。
 */

import { signCompactJwsAsync } from '../vc/compact-jws.js';
import type { CredentialSignerAlg } from '../vc/jws.js';
import { type AnyCredentialSigner, buildJwsHeader } from '../vc/signer.js';

/** VC Data Model 2.0 の `@context` 先頭要素（先頭でなければならない）。 */
const VC_DATA_MODEL_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** `issueVpJwtAsync` の入力（verifier バインド）。 */
export interface IssueVpJwtOptions {
  /** Verifier 識別子（OID4VP の `client_id`）。payload の `aud` に設定する。 */
  readonly audience: string;
  /** Verifier 発行の nonce（リプレイ対策）。payload の `nonce` に設定する。 */
  readonly nonce: string;
}

/**
 * VC を含まない VP を `vp+jwt`（コンパクト JWS）として署名する。
 *
 * header は `buildJwsHeader(signer, 'vp+jwt')`（`signer.kid` 設定時は `alg` と `typ` の間に `kid` を挿入する）、
 * payload は次のとおり:
 * - `@context` = `['https://www.w3.org/ns/credentials/v2']`
 * - `type`     = `['VerifiablePresentation']`
 * - `holder`   = `holder`（署名する DID）
 * - `aud` / `nonce` = `opts`
 *
 * @param holder VP の `holder`（署名鍵に対応する DID）。
 * @param signer 署名鍵（同期 / 非同期どちらも可。`alg` / `kid` を header に反映する）。
 * @param opts audience / nonce。
 * @returns コンパクト `vp+jwt` 文字列（`header.payload.signature`）。
 * @throws 署名演算・外部署名呼び出しが失敗した場合（VericertsError、code `1020`）。
 */
export async function issueVpJwtAsync(
  holder: string,
  signer: AnyCredentialSigner<CredentialSignerAlg>,
  opts: IssueVpJwtOptions,
): Promise<string> {
  const payload = {
    '@context': [VC_DATA_MODEL_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder,
    aud: opts.audience,
    nonce: opts.nonce,
  };
  return signCompactJwsAsync(buildJwsHeader(signer, 'vp+jwt'), payload, signer);
}
