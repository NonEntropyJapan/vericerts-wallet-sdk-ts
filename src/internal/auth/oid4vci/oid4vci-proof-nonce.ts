/**
 * JWT Proof の `nonce` の解決（OID4VCI 1.0 §7 / §8.2.1.1）。
 *
 * `receiveCredential`（facade）/ `receiveCredentialViaAuthorizationCode` / EUDI `receivePID` /
 * `receiveEAA` の 3 経路が同じ解決順を使う（経路ごとに書き写すと、片方だけ Nonce Endpoint 方式の
 * Issuer から受領できなくなる）。
 *
 * 解決順（OID4VCI 1.0 の Nonce Endpoint を優先し、旧 Draft の Token Response は互換として残す）:
 * 1. Issuer Metadata に `nonce_endpoint` があれば Nonce Endpoint（`requestCNonce`）から取得する
 *    （OID4VCI 1.0 Final の標準。EUDI / HAIP の Issuer はこの方式）。
 * 2. 無ければ Token Response の `c_nonce`（旧 Draft 互換）。
 * 3. どちらも無ければ `undefined`（Issuer は nonce を要求しない。proof は `nonce` 無しで生成する）。
 */

import type { FetchLike } from '../../fetch-di.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { requestCNonce } from '../eudi/issuance/nonce.js';

/**
 * Credential Request の JWT Proof に載せる `nonce` を解決する。
 *
 * @param tokenCNonce Token Response の `c_nonce`（無ければ `undefined`）。
 * @param nonceEndpoint Issuer Metadata の `nonce_endpoint`（HTTPS。無ければ `undefined`）。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム。
 * @returns proof の `nonce`。Issuer が nonce を要求しない場合は `undefined`。
 * @throws Nonce Endpoint の取得に失敗した場合（VericertsError）。
 */
export async function resolveProofNonce(
  tokenCNonce: string | undefined,
  nonceEndpoint: string | undefined,
  fetchImpl: FetchLike | undefined,
): Promise<string | undefined> {
  if (isNonBlankString(nonceEndpoint)) {
    return requestCNonce(nonceEndpoint, fetchImpl);
  }
  if (isNonBlankString(tokenCNonce)) {
    return tokenCNonce;
  }
  return undefined;
}
