/**
 * nonce 管理・replay 検知モジュールの内部バレル。
 *
 * - types.ts:              `NonceStore` / `NonceStoreAdapter` / `NonceContext` 等の型。
 * - 定数時間比較は `internal/timing-safe.ts`（credential 側からも使うため internal 直下）。
 * - generate.ts:           CSPRNG による生成とフォーマット / エントロピー検査（4013）。
 * - context.ts:            コンテキストの正規化とバインディング検査（4012）。
 * - context-keys.ts:       解決済み flow / 束縛値からの拒否リストキー組み立て。
 * - context-snapshot.ts:   replay ガード入口での `NonceContext` のスナップショット化（単一読み）。
 *                          guard / vp-guard が直接 import する内部ヘルパのため再 export しない。
 * - memory-adapter.ts:     インメモリの永続化アダプタ。
 * - キー単位の直列化ロックは `internal/primitives/key-lock.ts`（Foundation）。
 * - bloom-filter.ts:       高負荷時プリフィルタ。`store.ts` の内部ヘルパの
 *                          ため `BloomFilter` 自体は再 export しない（`capacity/capacity.ts` と同様）。
 * - store.ts:              seen-nonces cache の検知ロジックと `createNonceStore`。
 * - capacity/capacity.ts:  コンテキストあたりの容量上限維持と LRU / 期限切れ退避。
 *                          `store.ts` の内部ヘルパのため再 export しない。
 * - replay-window.ts:      クロック誤差許容範囲の検査（4014）。
 * - one-time-credential.ts: 一回限り使用 VC の `jti` 消費。
 * - guard.ts:              KB-JWT 検証経路への接続。
 * - vp-guard.ts:           JWT-VP 検証経路への接続。
 */

export { timingSafeEqualBytes, timingSafeEqualString } from '../../timing-safe.js';
export { DEFAULT_BLOOM_FALSE_POSITIVE_RATE } from './bloom-filter.js';
export {
  assertBinding,
  assertBindingMatches,
  bindingValueOf,
  DEFAULT_TTL_MS_BY_FLOW,
  defaultTtlMsFor,
  resolveBinding,
} from './context.js';
export { contextKeyFrom, contextKeyOf, entryKeyFrom, entryKeyOf } from './context-keys.js';
export {
  assertWellFormedNonce,
  generateNonce,
  isWellFormedNonce,
  MIN_NONCE_ENTROPY_BITS,
  MIN_NONCE_LENGTH,
} from './generate.js';
export { type ReplayGuardOptions, verifySdJwtWithReplayGuard } from './guard.js';
export { MemoryNonceStoreAdapter } from './memory-adapter.js';
export {
  type ConsumeOneTimeCredentialOptions,
  consumeOneTimeCredential,
  VP_NONCE_RETENTION_GRACE_MS,
  vpNonceRetentionMs,
} from './one-time-credential.js';
export {
  assertWithinReplayWindow,
  REPLAY_WINDOW_SECONDS_BY_FLOW,
  type ReplayWindowOptions,
} from './replay-window.js';
export { createNonceStore } from './store.js';
export { DEFAULT_MAX_ENTRIES, DEFAULT_SWEEP_INTERVAL_MS } from './store-options.js';
export type {
  BloomFilterOptions,
  CheckAndUseOptions,
  NonceContext,
  NonceEvictionReason,
  NonceFlow,
  NonceStore,
  NonceStoreAdapter,
  NonceStoreBackend,
  NonceStoreOptions,
  SeenNonceEntry,
} from './types.js';
export {
  type PresentationReplayGuardOptions,
  verifyPresentationWithReplayGuard,
} from './vp-guard.js';
