/**
 * JSON Schema（Draft 2020-12 サブセット）検証の内部バレル。
 *
 * W3C VC の `credentialSchema` 経路と SD-JWT VC の Type Metadata 経路の
 * 両方から共有される。両経路は別エコシステムとして扱うが、JSON Schema 検証プリミティブは共通。
 *
 * - types.ts:          `JsonSchema` / `SchemaError` / `SchemaValidationResult` /
 *                      `SchemaFailSafeResult`（FO-3 / FO-4 を両経路で共有する結果型）。
 * - validate.ts:       `validateAgainstSchema`（本体）。
 * - fetch-document.ts: HTTPS 限定のスキーマ文書取得（両経路で共有）。
 * - integrity.ts:      `assertNoUnverifiableIntegrity`（参照先文書のハッシュ固定宣言の拒否。両経路で共有）。
 * - internals.ts:      非公開ヘルパー（`$ref` 解決・深い等価判定など）。
 * - object-properties.ts: 非公開の `properties` / `patternProperties` / `additionalProperties`
 *                      割り当て（再帰を含まない部分）。
 * - scalar-keywords.ts: 非公開の非再帰キーワード検証（型 / 文字列 / 数値）。
 * 正規表現（`pattern` / `patternProperties`）は `internal/primitives/safe-regex` の線形時間エンジンで評価する。
 */

export {
  fetchSchemaJson,
  isHttpsUrl,
  MAX_SCHEMA_DOCUMENT_BYTES,
  SCHEMA_FETCH_TIMEOUT_MS,
  type SchemaFetchDependencies,
} from './fetch-document.js';
export {
  assertNoUnverifiableIntegrity,
  CREDENTIAL_SCHEMA_INTEGRITY_KEYS,
  INTEGRITY_UNVERIFIABLE_REASON,
  SD_JWT_VC_INTEGRITY_KEYS,
  TYPE_METADATA_INTEGRITY_KEYS,
} from './integrity.js';
export type {
  JsonSchema,
  SchemaError,
  SchemaFailSafeResult,
  SchemaValidationResult,
} from './types.js';
export { validateAgainstSchema } from './validate.js';
