/**
 * Credential Response の OID4VCI 1.0 §8.3 `credentials` 配列の読み取り。
 * `oid4vci-credential-response.ts` から行数上限のため分離。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';

/**
 * OID4VCI 1.0 §8.3 の `credentials` から VC を 1 件取り出す。配列でない・1 要素でない（Proof は 1 件しか送らない）・
 * `credential` が空 / 非文字列、`transaction_id`（§8.3 で併存 MUST NOT）・旧 `credential` との併存は `8020`。
 */
export function readCredentialsArray(
  credentials: unknown,
  legacyCredential: string | undefined,
  transactionId: string | undefined,
): string {
  if (legacyCredential !== undefined || transactionId !== undefined) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  }
  if (!Array.isArray(credentials) || credentials.length !== 1) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  }
  const entry: unknown = credentials[0];
  const credential =
    typeof entry === 'object' && entry !== null
      ? ownProperty<unknown>(entry, 'credential')
      : undefined;
  if (typeof credential !== 'string' || credential.length === 0) {
    throw new VericertsError(ErrorCodes.CREDENTIAL_REQUEST_FAILED);
  }
  return credential;
}
