/**
 * `NonceStore` のサイズ上限と退避のユニットテスト。
 *
 * nonce-store.test.ts の行数上限（linterly 300 行）を超えないための分離で、検証内容は同ファイルに
 * あったものと同じ系統。
 *
 * 検証内容:
 * - 満杯時は未使用エントリのみ LRU 退避し、TTL 内の使用済みは退避しない。
 * - 使用済みだけで満杯なら新規を 4010 で拒否する（fail-closed）。その拒否は replay 検知と
 *   `context.reason: 'capacity_exhausted'` で区別できる。
 * - 期限切れは LRU より優先して退避し、上限はコンテキストごとに独立している。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createNonceStore } from '../store.js';
import type { NonceContext, NonceEvictionReason, SeenNonceEntry } from '../types.js';

const NONCE_A = 'AQIDBAUGBwgJCgsMDQ4PEA';
const NONCE_B = 'BQIDBAUGBwgJCgsMDQ4PEA';
const CLIENT = 'https://verifier.example/client';
const CTX: NonceContext = { flow: 'oid4vp', clientId: CLIENT };

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

/** `VericertsError` の code を検査する（非同期版）。 */
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

describe('NonceStore: サイズ上限と退避', () => {
  it('満杯状態で新規挿入すると最古の未使用エントリが LRU 退避される', async () => {
    const evicted: { entry: SeenNonceEntry; reason: NonceEvictionReason }[] = [];
    const clock = makeClock();
    const store = createNonceStore({
      backend: 'memory',
      maxEntries: 3,
      now: clock.now,
      onEvict: (entry, reason) => evicted.push({ entry, reason }),
    });

    const nonces = ['A', 'B', 'C', 'D'].map((c) => `${c}QIDBAUGBwgJCgsMDQ4PEA`);
    for (const nonce of nonces) {
      await store.put(nonce, CTX, 600_000);
      clock.advance(10);
    }

    // 上限 3 に対し 4 件目を入れたので、最古（1 件目、未使用）が退避される。
    expect(evicted).toHaveLength(1);
    expect(evicted[0]?.reason).toBe('lru');
    expect(evicted[0]?.entry.nonce).toBe(nonces[0] as string);
  });

  it('TTL 内の使用済みエントリは LRU 退避されず、未使用だけが退避される', async () => {
    const evicted: string[] = [];
    const clock = makeClock();
    const store = createNonceStore({
      backend: 'memory',
      maxEntries: 3,
      now: clock.now,
      onEvict: (entry) => evicted.push(entry.nonce),
    });
    const [used, unusedOld, unusedNew, incoming] = ['A', 'B', 'C', 'D'].map(
      (c) => `${c}QIDBAUGBwgJCgsMDQ4PEA`,
    ) as [string, string, string, string];

    // 最古は使用済み。新しい 2 件は未使用。
    await store.checkAndUse(used, CTX, { ttlMs: 600_000 });
    clock.advance(10);
    await store.put(unusedOld, CTX, 600_000);
    clock.advance(10);
    await store.put(unusedNew, CTX, 600_000);
    clock.advance(10);
    await store.put(incoming, CTX, 600_000);

    // 古い順なら使用済みが先に退避されるが、未使用の最古だけが退避される。
    expect(evicted).toEqual([unusedOld]);
    expect(await store.has(used, CTX)).toBe(true);
    await expectCode(() => store.checkAndUse(used, CTX), ErrorCodes.REPLAY_DETECTED);
  });

  it('使用済みだけで満杯なら put を 4010 で拒否し、消費済み nonce は replay できない', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', maxEntries: 2, now: clock.now });
    const victim = 'VQIDBAUGBwgJCgsMDQ4PEA';
    await store.put(victim, CTX, 600_000);
    await store.checkAndUse(victim, CTX);
    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 600_000 });

    // 攻撃者が発行記録を流し込んでも、使用済みは退避されず新規は拒否される（fail-closed）。
    for (let i = 0; i < 5; i++) {
      clock.advance(1);
      await expectCode(
        () => store.put(`${String.fromCharCode(66 + i)}QIDBAUGBwgJCgsMDQ4PEA`, CTX, 600_000),
        ErrorCodes.REPLAY_DETECTED,
      );
    }
    await expectCode(() => store.checkAndUse(NONCE_B, CTX), ErrorCodes.REPLAY_DETECTED);
    await expectCode(() => store.checkAndUse(victim, CTX), ErrorCodes.REPLAY_DETECTED);
  });

  // 容量枯渇による拒否は replay の検知ではない。区別できないと、運用側は「攻撃を
  // 受けている」のか「maxEntries が足りずコンテキスト全体が TTL の間ロックアウトされている」
  // のかを判断できない。
  it('容量枯渇による 4010 は context.reason で replay 検知と区別できる', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', maxEntries: 1, now: clock.now });
    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 600_000 });

    let capacityError: unknown;
    try {
      await store.put(NONCE_B, CTX, 600_000);
    } catch (error) {
      capacityError = error;
    }
    expect((capacityError as VericertsError).code).toBe(ErrorCodes.REPLAY_DETECTED);
    expect((capacityError as VericertsError).context).toMatchObject({
      reason: 'capacity_exhausted',
    });

    // 本物の replay（同じ nonce の再消費）には reason が付かない。
    let replayError: unknown;
    try {
      await store.checkAndUse(NONCE_A, CTX);
    } catch (error) {
      replayError = error;
    }
    expect((replayError as VericertsError).code).toBe(ErrorCodes.REPLAY_DETECTED);
    expect((replayError as VericertsError).context?.reason).toBeUndefined();
  });

  it('使用済みが TTL 切れになれば枠は回収されて受理できる', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', maxEntries: 1, now: clock.now });
    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    await expectCode(() => store.put(NONCE_B, CTX, 1000), ErrorCodes.REPLAY_DETECTED);
    clock.advance(1001);
    await store.put(NONCE_B, CTX, 1000);
  });

  it('期限切れエントリは LRU より優先して退避される', async () => {
    const evicted: NonceEvictionReason[] = [];
    const clock = makeClock();
    const store = createNonceStore({
      backend: 'memory',
      maxEntries: 2,
      now: clock.now,
      onEvict: (_entry, reason) => evicted.push(reason),
    });

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    clock.advance(1001);
    await store.checkAndUse(NONCE_B, CTX, { ttlMs: 600_000 });

    expect(evicted).toEqual(['expired']);
  });

  it('上限はコンテキストごとに独立している', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', maxEntries: 1, now: clock.now });
    const other: NonceContext = { flow: 'oid4vp', clientId: 'https://other.example/client' };

    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 600_000 });
    await store.checkAndUse(NONCE_B, other, { ttlMs: 600_000 });

    expect(await store.has(NONCE_A, CTX)).toBe(true);
    expect(await store.has(NONCE_B, other)).toBe(true);
  });
});
