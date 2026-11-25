/**
 * `NonceStoreOptions` の既定値と、オプションから導出する部品。
 *
 * 検知ロジック本体（`store.ts` の `AdapterNonceStore`）から、オプション解決だけを分離したもの。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import { BloomFilter } from './bloom-filter.js';
import type { NonceStoreOptions } from './types.js';

/** 既定サイズ上限（コンテキストあたり）。 */
export const DEFAULT_MAX_ENTRIES = 10_000;

/** 既定 sweep 間隔（ms）。 */
export const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

/**
 * TTL が有効な正の有限数か検査する。
 *
 * @param ttlMs 検査対象。
 * @throws `RangeError` 正の有限数でない場合（呼び出し側の実装不良）。
 */
export function assertValidTtl(ttlMs: number | undefined): asserts ttlMs is number {
  if (ttlMs === undefined || !Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new RangeError(
      'ttlMs は正の有限数である必要があります（one-time-credential では明示指定が必須）',
    );
  }
}

/**
 * `NonceStoreOptions.bloomFilter` から `BloomFilter` を組み立てる（未指定・`false` なら `undefined`）。
 *
 * 初期容量は明示指定が無ければ `maxEntries`（コンテキストあたりの上限）を流用する。
 * 複数コンテキストを 1 インスタンスで扱う場合はフィルタ全体で共有する総件数がこれを超えうるが、
 * `BloomFilter` はレイヤー自動拡張（Scalable Bloom Filter）で偽陽性率の劣化を抑えるため、
 * 過小な初期見積りでも安全側に補正される。
 */
export function resolveBloomFilter(opts: NonceStoreOptions): BloomFilter | undefined {
  const bloomFilter = ownProperty<NonceStoreOptions['bloomFilter']>(opts, 'bloomFilter');
  if (bloomFilter === undefined || bloomFilter === false) {
    return undefined;
  }
  const config = bloomFilter === true ? undefined : bloomFilter;
  return new BloomFilter({
    capacity:
      (config === undefined ? undefined : ownProperty<number>(config, 'capacity')) ??
      ownProperty<number>(opts, 'maxEntries') ??
      DEFAULT_MAX_ENTRIES,
    falsePositiveRate:
      config === undefined ? undefined : ownProperty<number>(config, 'falsePositiveRate'),
  });
}
