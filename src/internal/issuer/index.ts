/**
 * issuer モジュールの公開エントリ。
 *
 * Token Status List（IETF draft-ietf-oauth-status-list）と
 * Bitstring Status List（W3C）の
 * 生成・更新・評価プリミティブと、Issuer / Verifier 双方の運用ヘルパーを再エクスポートする。
 * facade（`wallet.ts` / `index.ts`）への配線は統合担当が行う。
 */

export {
  compressBitstring,
  decompressBitstring,
  type StatusBits,
  StatusBitstring,
} from './bitstring.js';
export {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_ENTRY_TYPE,
  BITSTRING_STATUS_LIST_TYPE,
  BitstringStatusList,
  type BitstringStatusListCredentialOptions,
  type BitstringStatusListEntry,
  type BitstringStatusMessage,
  type BitstringStatusPurpose,
  type BitstringStatusResolverOptions,
  type BitstringStatusResult,
  type CreateBitstringStatusListEntryOptions,
  checkBitstringStatus,
  createBitstringStatusListEntry,
  MAX_BITSTRING_STATUS_SIZE,
  MIN_BITSTRING_STATUS_LIST_BITS,
  resolveBitstringStatus,
  signBitstringStatusListCredential,
  verifyBitstringStatusListCredential,
} from './bitstring-status-list/index.js';
export {
  type IssuedStatusEntry,
  type IssueOptions,
  IssuerModule,
  type IssuerModuleOptions,
  type StatusListType,
  type TokenStatusPurpose,
  type VCFormat,
} from './module/index.js';
export {
  cacheFetchedToken,
  createStatusListCache,
  lookupCachedToken,
  normalizeTokenResponse,
  type StatusListCacheDeps,
  type StatusListCacheEvent,
  type StatusListCacheLookup,
  type StatusListTokenResponse,
} from './status-list-cache.js';
export {
  createStatusListResolver,
  type StatusListResolverOptions,
} from './status-list-resolver.js';
export {
  type IssueTokenOptions,
  STATUS_LIST_TOKEN_TYP,
  type StatusListTokenInput,
  type StatusListTokenPayload,
  signStatusListToken,
  signStatusListTokenAsync,
} from './status-list-token.js';
export {
  readStatusBit,
  type VerifiedStatusListToken,
  verifyStatusListToken,
} from './status-list-token-verify.js';
export {
  type AllocatedStatusEntry,
  STATUS_VALUE_SET,
  STATUS_VALUE_VALID,
  type StatusListManagerOptions,
  type StatusListSnapshot,
  type StatusPurpose,
} from './status-list-types.js';
export {
  assertStatusValid,
  DEFAULT_STATUS_CACHE_MAX_TTL_SECONDS,
  evaluateCacheFreshness,
  evaluateStatusEntry,
  parseMaxAgeSeconds,
  type StatusCacheFreshness,
  type StatusCacheFreshnessInput,
  type StatusEntryState,
} from './status-list-verifier.js';
export { createStatusList, StatusListManager } from './token-status-list.js';
