/**
 * `prune` の委譲経路（`pruneExpired`）と従来のフォールバック経路が**観測上等価**であることの
 * 検証。
 *
 * 委譲は性能のための最適化であり、失効・リプレイ検知の判定を変えてはならない。
 * 「期限切れ判定の対象を先に削除してリプレイが通る」類のバグはこのコードベースで実際に
 * 起きているため、両経路の結果を突き合わせる差分テストを置く。
 *
 * **等価性の範囲に注意:** `count` 近道は「上限未達なら退避処理を行わない」という*意図された*
 * 観測差を持つ（挿入時の期限切れ先行削除が走らず、回収が遅延 sweep に寄る）。
 * 本ファイルが等価性を主張するのは `prune` の削除対象であって、容量管理の副作用ではない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { contextKeyOf } from '../../context-keys.js';
import { MemoryNonceStoreAdapter } from '../../memory-adapter.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore, NonceStoreAdapter, SeenNonceEntry } from '../../types.js';

const CTX: NonceContext = { flow: 'oid4vp', clientId: 'https://verifier.example/client' };
const LIVE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const DOOMED = 'BQIDBAUGBwgJCgsMDQ4PEA';
const FRESH = 'CQIDBAUGBwgJCgsMDQ4PEA';

/** 時刻を手動で進められるクロック。 */
function makeClock(start = 1_700_000_000_000): {
  now: () => number;
  advance: (ms: number) => void;
} {
  let current = start;
  return {
    now: () => current,
    advance: (ms: number) => {
      current += ms;
    },
  };
}

/** 任意メンバを持つ委譲アダプタ（redis / sqlite 相当）。sweep 委譲の実行回数を数える。 */
class FastAdapter implements NonceStoreAdapter {
  readonly #inner = new MemoryNonceStoreAdapter();
  pruneExpiredCalls = 0;

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
    return this.#inner.entries();
  }
  entriesByPrefix(prefix: string): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    return this.#inner.entriesByPrefix(prefix);
  }
  pruneExpired(now: number): Promise<number> {
    this.pruneExpiredCalls += 1;
    return this.#inner.pruneExpired(now);
  }
  count(prefix?: string): Promise<number> {
    return this.#inner.count(prefix);
  }

  /** 保持件数（テスト用）。 */
  get size(): number {
    return this.#inner.size;
  }
}

/** 任意メンバを持たない最小アダプタ（従来のフォールバック経路）。 */
class SlowAdapter implements NonceStoreAdapter {
  readonly #inner = new MemoryNonceStoreAdapter();

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
    return this.#inner.entries();
  }
}

/** 送出された `VericertsError` の code を返す。正常終了なら `'ok'`。 */
async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return 'ok';
  } catch (error) {
    return error instanceof VericertsError ? error.code : `unexpected:${String(error)}`;
  }
}

/**
 * 同一のシナリオをストアに適用し、観測できる結果だけを列に並べて返す。
 *
 * 期限切れ・未失効・初見・二重消費・prune 件数をすべて含め、経路差が出れば必ず列が変わるようにする。
 */
async function observe(store: NonceStore, clock: ReturnType<typeof makeClock>): Promise<string[]> {
  const out: string[] = [];
  await store.put(DOOMED, CTX, 1000);
  await store.checkAndUse(LIVE, CTX, { ttlMs: 600_000 });
  clock.advance(1001);

  out.push(`pruned=${await store.prune()}`);
  out.push(`live-has=${await store.has(LIVE, CTX)}`);
  out.push(`live-replay=${await codeOf(() => store.checkAndUse(LIVE, CTX))}`);
  // 期限切れ DOOMED の再提示。prune が実際に削除していれば「初見」として受理され、
  // 削除し損ねて残留していれば 4011 になる。`has()` は未消費エントリで常に false を
  // 返すため判別力が無く、この列が prune の削除を観測する唯一の証拠になる。
  out.push(`doomed-recheck=${await codeOf(() => store.checkAndUse(DOOMED, CTX, { ttlMs: 1000 }))}`);
  out.push(`fresh=${await codeOf(() => store.checkAndUse(FRESH, CTX, { ttlMs: 600_000 }))}`);
  out.push(`fresh-replay=${await codeOf(() => store.checkAndUse(FRESH, CTX))}`);
  return out;
}

describe('委譲経路とフォールバック経路の観測等価性', () => {
  it('同一シナリオで両経路の観測結果が一致する', async () => {
    const fastClock = makeClock();
    const fast = new FastAdapter();
    const fastResult = await observe(
      createNonceStore({ backend: 'redis', adapter: fast, now: fastClock.now }),
      fastClock,
    );

    const slowClock = makeClock();
    const slowResult = await observe(
      createNonceStore({ backend: 'sqlite', adapter: new SlowAdapter(), now: slowClock.now }),
      slowClock,
    );

    // 委譲が実際に使われたうえで結果が一致していること（委譲が無効なら前提が崩れる）。
    expect(fast.pruneExpiredCalls).toBeGreaterThan(0);
    expect(fastResult).toEqual(slowResult);
    // 期待値を直接も固定しておく（両経路が同時に壊れた場合に気付けるようにする）。
    expect(fastResult).toEqual([
      'pruned=1',
      'live-has=true',
      `live-replay=${ErrorCodes.REPLAY_DETECTED}`,
      'doomed-recheck=ok',
      'fresh=ok',
      `fresh-replay=${ErrorCodes.REPLAY_DETECTED}`,
    ]);
  });

  it('count 早期 return では期限切れが残留し、遅延 sweep で回収される', async () => {
    // 従来は挿入のたびに期限切れが退避されていたが、
    // 上限未達だと確定した場合は退避処理自体を行わないため、回収は prune に寄る。
    const clock = makeClock();
    const adapter = new FastAdapter();
    const store = createNonceStore({
      backend: 'redis',
      adapter,
      maxEntries: 100,
      now: clock.now,
      sweepIntervalMs: 3_600_000,
    });

    await store.checkAndUse(DOOMED, CTX, { ttlMs: 1000 });
    clock.advance(1001);
    await store.checkAndUse(FRESH, CTX, { ttlMs: 600_000 });

    // 上限未達なので期限切れ DOOMED は挿入時に退避されず残っている。
    expect(adapter.size).toBe(2);
    // 残留していても失効判定は毎回 expiresAt を見るため 4011 のまま（受理されない）。
    expect(await codeOf(() => store.checkAndUse(DOOMED, CTX))).toBe(ErrorCodes.NONCE_EXPIRED);
    // 回収は遅延 sweep の prune が行う。
    expect(await store.prune()).toBe(1);
    expect(adapter.size).toBe(1);
  });

  it('遅延 sweep が実際に委譲されても未失効エントリは消えない', async () => {
    const clock = makeClock();
    const adapter = new FastAdapter();
    const store = createNonceStore({
      backend: 'redis',
      adapter,
      now: clock.now,
      sweepIntervalMs: 10,
    });

    await store.checkAndUse(LIVE, CTX, { ttlMs: 600_000 });
    clock.advance(5000);
    // sweep 間隔を跨いだ挿入で `#maybeSweep` → `pruneExpired` が実際に走る。
    await store.checkAndUse(FRESH, CTX, { ttlMs: 600_000 });

    expect(adapter.pruneExpiredCalls).toBeGreaterThan(0);
    // 未失効の消費済みエントリが sweep で消えていたら、ここが 4010 ではなく成功してしまう。
    expect(await codeOf(() => store.checkAndUse(LIVE, CTX))).toBe(ErrorCodes.REPLAY_DETECTED);
  });
});

describe('MemoryNonceStoreAdapter の任意メンバ', () => {
  it('pruneExpired / count を実装している（既定バックエンドが遅い経路に落ちない）', () => {
    const adapter = new MemoryNonceStoreAdapter();
    expect(typeof adapter.pruneExpired).toBe('function');
    expect(typeof adapter.count).toBe('function');
  });

  it('count の前方一致は entriesByPrefix と一致し、全件指定は size と一致する', async () => {
    const other: NonceContext = { flow: 'oid4vp', clientId: 'https://other.example/client' };
    const adapter = new MemoryNonceStoreAdapter();
    const store = createNonceStore({ backend: 'redis', adapter });

    await store.checkAndUse(LIVE, CTX, { ttlMs: 600_000 });
    await store.checkAndUse(DOOMED, CTX, { ttlMs: 600_000 });
    await store.checkAndUse(LIVE, other, { ttlMs: 600_000 });

    const prefix = `${contextKeyOf(CTX)}|`;
    expect(await adapter.count(prefix)).toBe((await adapter.entriesByPrefix(prefix)).length);
    expect(await adapter.count(prefix)).toBe(2);
    expect(await adapter.count()).toBe(adapter.size);
    expect(await adapter.count()).toBe(3);
  });

  it('pruneExpired は期限切れだけを消して件数を返す', async () => {
    const clock = makeClock();
    const adapter = new MemoryNonceStoreAdapter();
    const store = createNonceStore({ backend: 'redis', adapter, now: clock.now });

    await store.checkAndUse(DOOMED, CTX, { ttlMs: 1000 });
    await store.checkAndUse(LIVE, CTX, { ttlMs: 600_000 });
    clock.advance(1001);

    expect(await adapter.pruneExpired(clock.now())).toBe(1);
    expect(adapter.size).toBe(1);
  });

  it('境界は expiresAt <= now（ちょうど期限の瞬間も削除する）', async () => {
    // `<=` を `<` に変えるとこのテストだけが落ちる。フォールバック経路（store.ts）も `<=` で
    // 判定するため、境界がずれると expiresAt === now のエントリで両経路の挙動が食い違う。
    const clock = makeClock();
    const adapter = new MemoryNonceStoreAdapter();
    const store = createNonceStore({ backend: 'redis', adapter, now: clock.now });

    await store.checkAndUse(DOOMED, CTX, { ttlMs: 1000 });
    clock.advance(1000);

    expect(await adapter.pruneExpired(clock.now())).toBe(1);
    expect(adapter.size).toBe(0);
  });
});
