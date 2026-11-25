/**
 * OpenID Federation Trust Framework の公開エントリ（内部バレル）。
 *
 * - federation-types.ts:      Entity Statement / Trust Chain の型定義。
 * - statement.ts:             Entity Statement のデコード・構造検証・署名検証プリミティブ。
 * - entity-configuration.ts: Entity Configuration 取得・自己署名検証。
 * - trust-chain.ts: Trust Chain 構築・信頼アンカー検証。
 * - key-revocation.ts:        Subordinate Statement の鍵無効化宣言（`revoked_keys`、FC-11）。
 * - statement-cache.ts:       Entity Statement のキャッシュ層（`iat`/`exp` 準拠 + 伝播 SLA 600 秒）。
 * - cache/entity-cache.ts:    Trust Chain 解決結果（`FederationEntityCache`）とその TTL キャッシュ。
 * - cache/statement-observability.ts: Entity Statement 取得のメトリクス計装。
 * - fail-open/: Entity Configuration 取得失敗時の Fail-open 判定（FO-6）。
 *
 * `cache/` は `entity-cache.ts` / `statement-observability.ts` をまとめただけのサブディレクトリで、
 * 意味的な区切りではなく `federation/` 直下のディレクトリ行数上限（linterly、2000 行）を超えたための
 * 分離である。
 */

export {
  createFederationEntityCache,
  type FederationEntityCache,
  federationEntityCacheTtlSeconds,
  toFederationEntityCache,
} from './cache/entity-cache.js';
export {
  createFederationStatementCache,
  FEDERATION_CACHE_MAX_TTL_SECONDS,
  type FederationCacheDeps,
  type FederationCacheEvent,
  type FederationStatementKind,
  statementCacheTtlSeconds,
} from './cache/statement-cache.js';
export {
  entityConfigurationUrl,
  type ResolveEntityConfigurationDeps,
  resolveEntityConfiguration,
  verifyEntityConfiguration,
} from './entity-configuration.js';
export type {
  EntityConfiguration,
  EntityMetadata,
  EntityStatement,
  FederationEntityMetadata,
  JsonWebKeySet,
  MetadataPolicy,
  MetadataPolicyOperators,
  RevokedKeyDeclaration,
  ScopedRevokedKeyDeclaration,
  TrustChain,
  TrustChainNode,
} from './federation-types.js';
export {
  assertKeyNotRevoked,
  collectRevokedKeys,
  findKeyRevocation,
  KEY_REVOCATION_PROPAGATION_MAX_SECONDS,
  parseRevokedKeys,
} from './revocation/key-revocation.js';
export {
  assertStatementTimeValid,
  decodeAndVerifyStatement,
  decodeAndVerifyStatementWithKey,
  decodeStatementJws,
  parseEntityStatement,
  selfJwksOf,
  type VerifiedStatement,
  verifyDecodedStatement,
} from './statement/statement.js';
export { verifyTrustAnchor } from './trust-anchor-verify.js';
export {
  assertCredentialKeyNotRevoked,
  type BuildTrustChainDeps,
  type BuildTrustChainOptions,
  buildTrustChain,
  jwksEqual,
  MAX_TRUST_CHAIN_LENGTH,
} from './trust-chain.js';
