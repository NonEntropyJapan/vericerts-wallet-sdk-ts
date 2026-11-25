/**
 * JAR 署名者の発行者同一性検証（`iss == client_id` / SubjectAltName ドメイン一致）。`jar-signature.ts` から分割した実体（Linterly 300 行/ファイル上限）。
 */

import { comparableOrigin } from '../../https-url.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseRpAccessCertificate } from '../../trust/rp-access/index.js';
import { jarFailure } from './jar-failure.js';

/**
 * `iss == client_id` と SubjectAltName == `client_id` == `response_uri` ドメインを確かめる。
 *
 * `client_id` 側は origin で比較する。`client_id` は HAIP §5.1 では HTTPS URL（`x509_san_uri`
 * / `redirect_uri` 系の prefixed 形式ではない）なので origin が取れる。取れない `client_id`
 * （スキームなし識別子）は本経路では拒否する — 証明書の SubjectAltName と突き合わせる相手が
 * 無くなり、署名者のドメインを確かめられないためである。
 */
export function requireIdentityBinding(
  payload: object,
  leafDer: Uint8Array,
  options: object,
): void {
  // クレームは own 限定で読む（鎖読みだと `client_id` / `iss` を**持たない** Request Object が
  // 汚染値を掴み、突き合わせが自動的に成立する）。
  const iss = ownProperty<unknown>(payload, 'iss');
  const clientId = ownProperty<unknown>(payload, 'client_id');
  const responseUri = ownProperty<unknown>(payload, 'response_uri');
  if (!isNonBlankString(iss) || !isNonBlankString(clientId) || iss !== clientId) {
    throw jarFailure('jar_iss_client_id_mismatch');
  }
  const expectedClientId = ownProperty<unknown>(options, 'expectedClientId');
  if (isNonBlankString(expectedClientId) && expectedClientId !== clientId) {
    // deep link の相手と署名した相手が違う。
    throw jarFailure('jar_client_id_mismatch');
  }
  const clientOrigin = comparableOrigin(clientId);
  if (clientOrigin === undefined) {
    throw jarFailure('jar_client_id_not_url');
  }
  if (!isNonBlankString(responseUri) || comparableOrigin(responseUri) !== clientOrigin) {
    // `parseJarRequest` も同じ検査を行うが、署名検証の段で先に落とす。
    throw jarFailure('jar_response_uri_domain_mismatch');
  }
  const sanOrigin = subjectAltNameOrigin(leafDer);
  if (sanOrigin === undefined || sanOrigin !== clientOrigin) {
    throw jarFailure('jar_san_client_id_mismatch');
  }
}

/** `x5c` 先頭証明書の SubjectAltName（URI 形式）の origin。取り出せなければ `undefined`。 */
function subjectAltNameOrigin(leafDer: Uint8Array): string | undefined {
  let origin: string;
  try {
    origin = parseRpAccessCertificate(leafDer).identity.origin;
  } catch {
    return undefined;
  }
  return isNonBlankString(origin) ? comparableOrigin(origin) : undefined;
}
