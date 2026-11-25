/**
 * `ChainVerificationCache` の保持量の上限と期限切れ掃引。
 *
 * 件数・総量の上限も期限切れの掃引も無く、相異なる `vcId` を検証し続けるだけで `entries` が単調に増えた
 * （26 万件で約 1.09 GB）。`size`（保持件数）で決定的に pin する。形状を変えて検証する:
 * 多数の小さな結果 / 少数の巨大な結果（長い `vcId`・多ノード）/ 期限切れの掃引 / LRU。
 */

import { describe, expect, it } from 'bun:test';
import { DEFAULT_CACHE_MAX_ENTRIES } from '../../../../cache/ttl-cache.js';
import { ChainVerificationCache } from '../../cache.js';
import type { ChainVerificationResult } from '../../types.js';

const TTL = 300_000;

function resultOf(vcId: string, nodeIds: readonly string[] = [vcId]): ChainVerificationResult {
  return {
    vcId,
    valid: true,
    depth: 0,
    chain: nodeIds.map((id) => ({ vcId: id, relation: 'derivedFrom' as const, valid: true })),
  };
}

describe('ChainVerificationCache の保持量', () => {
  it('多数の小さな結果: 件数は maxEntries で頭打ちになり、古いものから追い出される', () => {
    const cache = new ChainVerificationCache();
    const total = DEFAULT_CACHE_MAX_ENTRIES * 4;
    for (let i = 0; i < total; i += 1) {
      cache.set(`k${i}`, resultOf(`k${i}`), 1_000);
    }
    expect(cache.size).toBe(DEFAULT_CACHE_MAX_ENTRIES);
    expect(cache.get('k0', 1_000)).toBeUndefined();
    expect(cache.get(`k${total - 1}`, 1_000)).toBeDefined();
  });

  it('少数の巨大な結果: 件数が上限未満でも重みの総量で追い出す（長い vcId・多ノード）', () => {
    const cache = new ChainVerificationCache(TTL, 256, 20_000);
    const long = 'x'.repeat(4_000);
    cache.set('a', resultOf(long), 0);
    cache.set('b', resultOf(long), 0);
    expect(cache.size).toBe(2);
    // 3 件目で総量上限を超えるので、最も古い 'a' が追い出される。
    cache.set('c', resultOf(long), 0);
    expect(cache.size).toBe(2);
    expect(cache.get('a', 0)).toBeUndefined();
    expect(cache.get('b', 0)).toBeDefined();
  });

  it('単独で総量上限を超える結果は保存しない（既存エントリも巻き添えにしない）', () => {
    const cache = new ChainVerificationCache(TTL, 256, 1_000);
    cache.set('small', resultOf('s'), 0);
    cache.set('huge', resultOf('h'.repeat(5_000)), 0);
    expect(cache.get('huge', 0)).toBeUndefined();
    expect(cache.get('small', 0)).toBeDefined();
  });

  it('set のたびに期限切れの全エントリを掃引する（同じキーを get しなくても解放される）', () => {
    const cache = new ChainVerificationCache();
    for (let i = 0; i < 100; i += 1) {
      cache.set(`old${i}`, resultOf(`old${i}`), 0);
    }
    expect(cache.size).toBe(100);
    cache.set('fresh', resultOf('fresh'), TTL);
    expect(cache.size).toBe(1);
    expect(cache.get('fresh', TTL)).toBeDefined();
  });

  it('相異なる vcId を TTL を超えて流し続けても、保持件数は常に 1 件以下で増えない', () => {
    const cache = new ChainVerificationCache();
    let peak = 0;
    for (let i = 0; i < 5_000; i += 1) {
      cache.set(`root:${i}`, resultOf(`root:${i}`), i * TTL);
      peak = Math.max(peak, cache.size);
    }
    expect(peak).toBe(1);
  });

  it('get で触れたエントリは最近使った扱いになり、追い出しの最後になる（LRU）', () => {
    const cache = new ChainVerificationCache(TTL, 2);
    cache.set('a', resultOf('a'), 0);
    cache.set('b', resultOf('b'), 0);
    expect(cache.get('a', 0)).toBeDefined();
    cache.set('c', resultOf('c'), 0);
    expect(cache.get('b', 0)).toBeUndefined();
    expect(cache.get('a', 0)).toBeDefined();
    expect(cache.get('c', 0)).toBeDefined();
  });

  it('有限でない now では保存しない（storedAt が NaN だと TTL 判定が常に偽になり永久に残る）', () => {
    const cache = new ChainVerificationCache();
    cache.set('k', resultOf('k'), Number.NaN);
    expect(cache.size).toBe(0);
  });

  it('invalidateChain は該当エントリを削除し、重みの合計も戻る（以降の追い出し判定が狂わない）', () => {
    const cache = new ChainVerificationCache(TTL, 256, 3_000);
    cache.set('a', resultOf('a', ['a', 'parent']), 0);
    cache.invalidateChain('parent', 0);
    expect(cache.size).toBe(0);
    // 総量が戻っていなければ、以降の保存が上限超過として弾かれる。
    cache.set('b', resultOf('b'), 0);
    cache.set('c', resultOf('c'), 0);
    expect(cache.size).toBe(2);
  });
});
