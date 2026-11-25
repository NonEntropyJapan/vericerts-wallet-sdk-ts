/**
 * VericertsError のコード → 定義レジストリ（schemas/error-codes.json）。
 *
 * `errors.ts` から分離してファイルサイズを抑える（ErrorCodes と VericertsError は errors.ts 側に残す）。
 * 定義本体はドメイン別ファイル（`error-registry/*.ts`）に切り出し、本ファイルはそれらを結合して
 * `ERROR_REGISTRY` として集約する。`message` には秘密情報を一切含めない。
 */

import { ACCOUNT_PROTOCOL_ERRORS } from './error-registry/account-protocol.js';
import { CREDENTIAL_ERRORS } from './error-registry/credential.js';
import type { ErrorDefinition } from './error-registry/definition.js';
import { DIDCOMM_ERRORS } from './error-registry/didcomm.js';
import { KEY_DID_ERRORS } from './error-registry/key-did.js';
import { STORAGE_ERRORS } from './error-registry/storage.js';
import { TRUST_EUDI_ERRORS } from './error-registry/trust-eudi.js';
import type { ErrorCode } from './errors.js';

/**
 * コード → 定義のレジストリ。ドメイン別の部分レジストリを結合する。
 * すべての `ErrorCode` を網羅する（型は `Record<ErrorCode, ErrorDefinition>`）。
 */
export const ERROR_REGISTRY: Record<ErrorCode, ErrorDefinition> = {
  ...KEY_DID_ERRORS,
  ...CREDENTIAL_ERRORS,
  ...ACCOUNT_PROTOCOL_ERRORS,
  ...TRUST_EUDI_ERRORS,
  ...STORAGE_ERRORS,
  ...DIDCOMM_ERRORS,
} as Record<ErrorCode, ErrorDefinition>;
