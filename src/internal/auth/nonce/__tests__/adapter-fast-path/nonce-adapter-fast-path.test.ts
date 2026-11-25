/**
 * `NonceStoreAdapter` の任意メンバ `pruneExpired` / `count` への委譲のユニットテスト。
 *
 * 検証内容:
 * - `prune()` が `pruneExpired` を持つアダプタへ委譲し、`entries()` で全件を引き上げない。
 * - 容量未達の挿入が `count` だけで判定され、エントリ本体を取得しない。
 * - `onEvict` 登録時は高速経路を使わず `NONCE_EVICTED` 監査を落とさない。
 * - 任意メンバを持たないアダプタは従来どおり `entries()` へフォールバックする（下位互換）。
 * - 委譲しても失効・リプレイ検知の判定が変わらない（未失効エントリを消さない）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { contextKeyOf } from '../../context-keys.js';
import { MemoryNonceStoreAdapter } from '../../memory-adapter.js';
import { createNonceStore } from '../../store.js';
import type {
  NonceContext,
  NonceEvictionReason,
  NonceStoreAdapter,
  SeenNonceEntry,
} from '../../types.js';

const NONCE_A = 'AQIDBAUGBwgJCgsMDQ4PEA';
const NONCE_B = 'BQIDBAUGBwgJCgsMDQ4PEA';
const CTX: NonceContext = { flow: 'oid4vp', clientId: 'https://verifier.example/client' };
const OTHER: NonceContext = { flow: 'oid4vp', clientId: 'https://other.example/client' };

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

/** 各メソッドの呼び出し回数を数える計装アダプタ（任意メンバを全部持つ）。 */
class FullAdapter implements NonceStoreAdapter {
  readonly inner = new MemoryNonceStoreAdapter();
  entriesCalls = 0;
  entriesByPrefixCalls = 0;
  pruneExpiredCalls = 0;
  countCalls = 0;
  countArgs: (string | undefined)[] = [];
  lastPruneNow: number | undefined;

  get(key: string): Promise<SeenNonceEntry | undefined> {
    return this.inner.get(key);
  }
  set(key: string, entry: SeenNonceEntry): Promise<void> {
    return this.inner.set(key, entry);
  }
  delete(key: string): Promise<void> {
    return this.inner.delete(key);
  }
  entries(): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    this.entriesCalls += 1;
    return this.inner.entries();
  }
  entriesByPrefix(prefix: string): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    this.entriesByPrefixCalls += 1;
    return this.inner.entriesByPrefix(prefix);
  }
  pruneExpired(now: number): Promise<number> {
    this.pruneExpiredCalls += 1;
    this.lastPruneNow = now;
    return this.inner.pruneExpired(now);
  }
  count(prefix?: string): Promise<number> {
    this.countCalls += 1;
    this.countArgs.push(prefix);
    return this.inner.count(prefix);
  }
}

/** 任意メンバを一切持たない最小アダプタ（下位互換の確認用）。 */
class MinimalAdapter implements NonceStoreAdapter {
  readonly inner = new MemoryNonceStoreAdapter();
  entriesCalls = 0;

  get(key: string): Promise<SeenNonceEntry | undefined> {
    return this.inner.get(key);
  }
  set(key: string, entry: SeenNonceEntry): Promise<void> {
    return this.inner.set(key, entry);
  }
  delete(key: string): Promise<void> {
    return this.inner.delete(key);
  }
  entries(): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    this.entriesCalls += 1;
    return this.inner.entries();
  }
}

/** `VericertsError` の code を検査する。 */
async function expectCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code as never);
    return;
  }
  throw new Error('例外が送出されなかった');
}

describe('prune(): pruneExpired への委譲', () => {
  it('pruneExpired を持つアダプタでは全件フェッチ（entries）が起きない', async () => {
    const clock = makeClock();
    const adapter = new FullAdapter();
    const store = createNonceStore({ backend: 'redis', adapter, now: clock.now });

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    const before = adapter.entriesCalls;
    clock.advance(1001);

    expect(await store.prune()).toBe(1);
    expect(adapter.pruneExpiredCalls).toBe(1);
    expect(adapter.entriesCalls).toBe(before);
  });

  it('委譲時も判定基準は注入されたクロック（アダプタ自前の時計を使わない）', async () => {
    const clock = makeClock(1_800_000_000_000);
    const adapter = new FullAdapter();
    const store = createNonceStore({ backend: 'redis', adapter, now: clock.now });

    clock.advance(5000);
    await store.prune();
    expect(adapter.lastPruneNow).toBe(1_800_000_005_000);
  });

  it('委譲しても未失効エントリは消えず、リプレイは 4010 のまま', async () => {
    const clock = makeClock();
    const adapter = new FullAdapter();
    const store = createNonceStore({ backend: 'redis', adapter, now: clock.now });

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 600_000 });
    await store.checkAndUse(NONCE_B, CTX, { ttlMs: 1000 });
    clock.advance(1001);

    expect(await store.prune()).toBe(1);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.REPLAY_DETECTED);
  });

  it('期限切れ判定は sweep より先に行われる（判定対象を先に消さない）', async () => {
    const clock = makeClock();
    const adapter = new FullAdapter();
    const store = createNonceStore({
      backend: 'redis',
      adapter,
      now: clock.now,
      sweepIntervalMs: 10,
    });

    await store.put(NONCE_A, CTX, 1000);
    clock.advance(5000);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.NONCE_EXPIRED);
    // 4011 を投げた時点で sweep は 1 度も走っていない。順序が逆なら判定対象そのものが
    // 消えて「初見」として受理される。
    expect(adapter.pruneExpiredCalls).toBe(0);
  });

  it('onEvict 登録時は委譲せず NONCE_EVICTED を発火する', async () => {
    const clock = makeClock();
    const adapter = new FullAdapter();
    const evicted: { nonce: string; reason: NonceEvictionReason }[] = [];
    const store = createNonceStore({
      backend: 'redis',
      adapter,
      now: clock.now,
      onEvict: (entry, reason) => evicted.push({ nonce: entry.nonce, reason }),
    });

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    clock.advance(1001);

    expect(await store.prune()).toBe(1);
    expect(adapter.pruneExpiredCalls).toBe(0);
    expect(evicted).toEqual([{ nonce: NONCE_A, reason: 'expired' }]);
  });

  it('任意メンバを持たないアダプタは entries() へフォールバックする（下位互換）', async () => {
    const clock = makeClock();
    const adapter = new MinimalAdapter();
    const store = createNonceStore({ backend: 'sqlite', adapter, now: clock.now });

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    await store.checkAndUse(NONCE_B, CTX, { ttlMs: 600_000 });
    const before = adapter.entriesCalls;
    clock.advance(1001);

    expect(await store.prune()).toBe(1);
    expect(adapter.entriesCalls).toBe(before + 1);
    // 「期限切れのみ」削除されること: 未失効エントリは残り、再提示は 4010 のまま。
    expect(await store.has(NONCE_A, CTX)).toBe(false);
    expect(await store.has(NONCE_B, CTX)).toBe(true);
    await expectCode(() => store.checkAndUse(NONCE_B, CTX), ErrorCodes.REPLAY_DETECTED);
  });
});

describe('容量管理: count による本体取得の回避', () => {
  it('上限未達の挿入ではエントリ本体を取得しない', async () => {
    const clock = makeClock();
    const adapter = new FullAdapter();
    const store = createNonceStore({
      backend: 'redis',
      adapter,
      maxEntries: 10,
      now: clock.now,
    });

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 600_000 });

    expect(adapter.countCalls).toBe(1);
    // 件数はコンテキスト前方一致で数えること（全件を数える実装だと上限判定が狂う）。
    expect(adapter.countArgs).toEqual([`${contextKeyOf(CTX)}|`]);
    expect(adapter.entriesByPrefixCalls).toBe(0);
    expect(adapter.entriesCalls).toBe(0);
  });

  it('上限に達したら本体を取得して LRU 退避する', async () => {
    const clock = makeClock();
    const adapter = new FullAdapter();
    const store = createNonceStore({ backend: 'redis', adapter, maxEntries: 1, now: clock.now });

    // 退避できるのは未使用（put のみ）のエントリだけ。
    await store.put(NONCE_A, CTX, 600_000);
    clock.advance(10);
    await store.checkAndUse(NONCE_B, CTX, { ttlMs: 600_000 });

    expect(adapter.entriesByPrefixCalls).toBeGreaterThan(0);
    expect(adapter.entriesCalls).toBe(0);
    expect(adapter.inner.size).toBe(1);
    expect(await store.has(NONCE_B, CTX)).toBe(true);
  });

  it('count はコンテキスト境界を越えず、他コンテキストの枠を食わない', async () => {
    const clock = makeClock();
    const adapter = new FullAdapter();
    const store = createNonceStore({ backend: 'redis', adapter, maxEntries: 1, now: clock.now });

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 600_000 });
    await store.checkAndUse(NONCE_B, OTHER, { ttlMs: 600_000 });

    expect(await store.has(NONCE_A, CTX)).toBe(true);
    expect(await store.has(NONCE_B, OTHER)).toBe(true);
  });

  it('onEvict 登録時は count の近道を使わず期限切れ退避の監査が挿入時に出る', async () => {
    const clock = makeClock();
    const adapter = new FullAdapter();
    const evicted: NonceEvictionReason[] = [];
    const store = createNonceStore({
      backend: 'redis',
      adapter,
      maxEntries: 10,
      now: clock.now,
      onEvict: (_entry, reason) => evicted.push(reason),
    });

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    clock.advance(1001);
    await store.checkAndUse(NONCE_B, CTX, { ttlMs: 600_000 });

    expect(adapter.countCalls).toBe(0);
    expect(evicted).toEqual(['expired']);
  });
});
