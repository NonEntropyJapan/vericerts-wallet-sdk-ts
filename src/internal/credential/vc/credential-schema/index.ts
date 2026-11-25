/**
 * VC JSON Schema 検証（W3C `credentialSchema`）の内部バレル。
 *
 * - types.ts:    TTL / 受理する `type` / オプション型。
 * - cache.ts:    スキーマ URL キーの TTL キャッシュ。
 * - validate.ts: URL 解決 → HTTPS 取得 → `credentialSubject` の検証。例外を投げる入口
 *   （`validateCredentialSchema`）と FO-3 / FO-4 に従う fail-open 入口
 *   （`validateClaimsAgainstCredentialSchema`）の 2 系統。
 */

export { CredentialSchemaCache } from './cache.js';
export {
  CREDENTIAL_SCHEMA_CACHE_TTL_MS,
  JSON_SCHEMA_CREDENTIAL_TYPES,
  type ValidateCredentialSchemaOptions,
} from './types.js';
export {
  resolveSchemaUrl,
  validateClaimsAgainstCredentialSchema,
  validateCredentialSchema,
} from './validate.js';
