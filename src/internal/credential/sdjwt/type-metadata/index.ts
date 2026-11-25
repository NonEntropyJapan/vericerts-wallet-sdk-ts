/**
 * SD-JWT VC Type Metadata（draft-ietf-oauth-sd-jwt-vc §6）の内部バレル。
 *
 * - types.ts:   Type Metadata の型・オプション型・TTL / 深さ上限などの定数。
 * - fetch.ts:   HTTPS 取得と構造検証（`vct` 一致・`schema` / `schema_uri` 排他）。
 * - cache.ts:   URL キーの TTL キャッシュ。
 * - resolve.ts: `extends` 継承の解決とクレーム構造検証（FO-3 / FO-4 準拠）。
 */

export { TypeMetadataCache } from './cache.js';
export {
  assertTypeMetadata,
  fetchSchemaDocument,
  fetchTypeMetadataDocument,
  isTypeMetadataUrl,
} from './fetch.js';
export { resolveTypeMetadata, validateClaimsAgainstTypeMetadata } from './resolve.js';
export {
  MAX_EXTENDS_DEPTH,
  type ResolvedTypeMetadata,
  type ResolveTypeMetadataOptions,
  type SdJwtTypeMetadata,
  TYPE_METADATA_CACHE_TTL_MS,
  TYPE_METADATA_TIMEOUT_MS,
  type TypeMetadataDependencies,
  type TypeMetadataValidationResult,
} from './types.js';
