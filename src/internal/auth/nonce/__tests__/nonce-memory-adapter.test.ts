/**
 * `MemoryNonceStoreAdapter.entriesByPrefix` のユニットテスト。
 *
 * 検証内容:
 * - 前方一致したエントリだけを挿入順で返す（LRU 退避が挿入順を前提とする）。
 * - コンテキスト境界（`|`）を越えて別コンテキストのエントリを拾わない。
 * - 回帰: SDK 内蔵アダプタが `entriesByPrefix` を実装しており、`NonceStore` の容量管理が
 *   `entries()` フォールバック（挿入のたびにキャッシュ全体を配列コピーする経路）へ落ちない。
 */

import { describe, expect, it } from 'bun:test';
import { contextKeyOf, entryKeyOf } from '../context-keys.js';
import { MemoryNonceStoreAdapter } from '../memory-adapter.js';
import { createNonceStore } from '../store.js';
import type { NonceContext, NonceStoreAdapter, SeenNonceEntry } from '../types.js';

const CTX_A: NonceContext = { flow: 'oid4vp', clientId: 'https://rp-a.example' };
const CTX_B: NonceContext = { flow: 'oid4vp', clientId: 'https://rp-b.example' };
const NOW = 1_700_000_000_000;

/** 指定コンテキストの容量管理プレフィックス（`capacity.ts` の `NonceCapacityManager#enforceCapacity` と同形）。 */
function prefixOf(ctx: NonceContext): string {
  return `${contextKeyOf(ctx)}|`;
}

/** テスト用のエントリを組み立てる。 */
function entryOf(nonce: string, ctx: NonceContext): SeenNonceEntry {
  return { nonce, context: ctx, firstSeenAt: NOW, expiresAt: NOW + 300_000 };
}

/** `MemoryNonceStoreAdapter` に nonce 群を順に書き込む。 */
async function seed(
  adapter: MemoryNonceStoreAdapter,
  pairs: readonly (readonly [string, NonceContext])[],
): Promise<void> {
  for (const [nonce, ctx] of pairs) {
    await adapter.set(entryKeyOf(nonce, ctx), entryOf(nonce, ctx));
  }
}

/** `entries()` / `entriesByPrefix()` の呼び出し回数を数える委譲アダプタ。 */
class CountingAdapter implements NonceStoreAdapter {
  readonly #inner = new MemoryNonceStoreAdapter();
  entriesCalls = 0;
  entriesByPrefixCalls = 0;
  pruneExpiredCalls = 0;
  countCalls = 0;

  get(key: string): Promise<SeenNonceEntry | undefined> {
    return this.#inner.get(key);
  }

  set(key: string, entry: SeenNonceEntry): Promise<void> {
    return this.#inner.set(key, entry);
  }

  delete(key: string): Promise<void> {
    return this.#inner.delete(key);
  }

  entries(): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    this.entriesCalls += 1;
    return this.#inner.entries();
  }

  entriesByPrefix(prefix: string): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    this.entriesByPrefixCalls += 1;
    return this.#inner.entriesByPrefix(prefix);
  }

  pruneExpired(now: number): Promise<number> {
    this.pruneExpiredCalls += 1;
    return this.#inner.pruneExpired(now);
  }

  count(prefix?: string): Promise<number> {
    this.countCalls += 1;
    return this.#inner.count(prefix);
  }
}

describe('MemoryNonceStoreAdapter.entriesByPrefix', () => {
  it('前方一致したエントリだけを挿入順で返す', async () => {
    const adapter = new MemoryNonceStoreAdapter();
    await seed(adapter, [
      ['AQIDBAUGBwgJCgsMDQ4PEA', CTX_A],
      ['BQIDBAUGBwgJCgsMDQ4PEA', CTX_B],
      ['CQIDBAUGBwgJCgsMDQ4PEA', CTX_A],
    ]);

    const matched = await adapter.entriesByPrefix(prefixOf(CTX_A));
    expect(matched.map((pair) => pair[1].nonce)).toEqual([
      'AQIDBAUGBwgJCgsMDQ4PEA',
      'CQIDBAUGBwgJCgsMDQ4PEA',
    ]);
  });

  it('一致するエントリが無ければ空配列を返す', async () => {
    const adapter = new MemoryNonceStoreAdapter();
    await seed(adapter, [['AQIDBAUGBwgJCgsMDQ4PEA', CTX_A]]);

    expect(await adapter.entriesByPrefix(prefixOf(CTX_B))).toEqual([]);
    expect(await adapter.entriesByPrefix('siopv2:')).toEqual([]);
  });

  it('別コンテキストのエントリを拾わない（キー境界の `|` を跨がない）', async () => {
    const adapter = new MemoryNonceStoreAdapter();
    const evil: NonceContext = { flow: 'oid4vp', clientId: 'https://rp-a.example|extra' };
    await seed(adapter, [
      ['AQIDBAUGBwgJCgsMDQ4PEA', CTX_A],
      ['BQIDBAUGBwgJCgsMDQ4PEA', evil],
    ]);

    const matched = await adapter.entriesByPrefix(prefixOf(CTX_A));
    expect(matched).toHaveLength(1);
    expect(matched[0]?.[1].context).toEqual(CTX_A);
  });

  it('`entries()` と同じ全件を返す（プレフィックスが全キーに一致する場合）', async () => {
    const adapter = new MemoryNonceStoreAdapter();
    await seed(adapter, [
      ['AQIDBAUGBwgJCgsMDQ4PEA', CTX_A],
      ['CQIDBAUGBwgJCgsMDQ4PEA', CTX_A],
    ]);

    expect(await adapter.entriesByPrefix('')).toEqual(await adapter.entries());
  });
});

describe('回帰: 内蔵アダプタが entries() フォールバックへ落ちない', () => {
  it('MemoryNonceStoreAdapter は entriesByPrefix を実装している', () => {
    expect(typeof new MemoryNonceStoreAdapter().entriesByPrefix).toBe('function');
  });

  it('上限未達の容量管理は count だけで済み、エントリ本体を取得しない', async () => {
    // `CountingAdapter` は `MemoryNonceStoreAdapter` と同じ任意メンバを持つため、
    // 既定バックエンドの実経路をそのまま再現する。
    const adapter = new CountingAdapter();
    const store = createNonceStore({
      backend: 'memory',
      adapter,
      now: () => NOW,
      sweepIntervalMs: 3_600_000,
    });

    await store.put('AQIDBAUGBwgJCgsMDQ4PEA', CTX_A, 300_000);
    await store.checkAndUse('AQIDBAUGBwgJCgsMDQ4PEA', CTX_A);
    await store.checkAndUse('CQIDBAUGBwgJCgsMDQ4PEA', CTX_B);

    expect(adapter.countCalls).toBeGreaterThan(0);
    expect(adapter.entriesByPrefixCalls).toBe(0);
    expect(adapter.entriesCalls).toBe(0);
  });

  it('上限到達時は entriesByPrefix が使われ entries() に落ちない', async () => {
    const adapter = new CountingAdapter();
    const store = createNonceStore({
      backend: 'memory',
      adapter,
      maxEntries: 1,
      now: () => NOW,
      sweepIntervalMs: 3_600_000,
    });

    // 退避できるのは未使用（put のみ）のエントリだけ。
    await store.put('AQIDBAUGBwgJCgsMDQ4PEA', CTX_A, 600_000);
    await store.checkAndUse('CQIDBAUGBwgJCgsMDQ4PEA', CTX_A);

    expect(adapter.entriesByPrefixCalls).toBeGreaterThan(0);
    expect(adapter.entriesCalls).toBe(0);
  });

  it('MemoryNonceStoreAdapter は pruneExpired / count も実装している', () => {
    const adapter = new MemoryNonceStoreAdapter();
    expect(typeof adapter.pruneExpired).toBe('function');
    expect(typeof adapter.count).toBe('function');
  });
});
