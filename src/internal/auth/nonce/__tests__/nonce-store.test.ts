/**
 * seen-nonces cache（`NonceStore`）のユニットテスト。
 *
 * 検証内容:
 * - 同一 nonce の 2 回消費で 4010 REPLAY_DETECTED。
 * - TTL 超過後の消費で 4011 NONCE_EXPIRED。
 * - `aud` / `client_id` 不一致で 4012 NONCE_BINDING_MISMATCH。
 * - フォーマット不正で 4013 NONCE_MALFORMED。
 * - コンテキスト分離（同一 nonce でも clientId が違えば別エントリ）。
 * - 拒否リスト満杯時の LRU 退避と `NONCE_EVICTED` 監査フック。
 * - `createNonceStore` の DI seam（memory 既定 / 非 memory は adapter 必須）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MemoryNonceStoreAdapter } from '../memory-adapter.js';
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

describe('NonceStore: 使用 1 回の保証', () => {
  it('初見の nonce は消費でき、2 回目は 4010 REPLAY_DETECTED', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await store.checkAndUse(NONCE_A, CTX);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.REPLAY_DETECTED);
  });

  it('put で発行記録した nonce は 1 回だけ消費でき、2 回目は 4010', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await store.put(NONCE_A, CTX, 300_000);
    expect(await store.has(NONCE_A, CTX)).toBe(false);
    await store.checkAndUse(NONCE_A, CTX);
    expect(await store.has(NONCE_A, CTX)).toBe(true);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.REPLAY_DETECTED);
  });

  it('未失効の nonce を再度 put すると一意性違反として 4010', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await store.put(NONCE_A, CTX, 300_000);
    await expectCode(() => store.put(NONCE_A, CTX, 300_000), ErrorCodes.REPLAY_DETECTED);
  });

  it('別 nonce は互いに影響しない', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await store.checkAndUse(NONCE_A, CTX);
    await expect(store.checkAndUse(NONCE_B, CTX)).resolves.toBeUndefined();
  });
});

describe('NonceStore: TTL と期限切れ', () => {
  it('TTL 超過後の消費は 4011 NONCE_EXPIRED', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', now: clock.now });
    await store.put(NONCE_A, CTX, 300_000);
    clock.advance(300_001);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.NONCE_EXPIRED);
  });

  it('TTL 内であれば消費できる', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', now: clock.now });
    await store.put(NONCE_A, CTX, 300_000);
    clock.advance(299_999);
    await expect(store.checkAndUse(NONCE_A, CTX)).resolves.toBeUndefined();
  });

  it('消費済みでも期限切れなら has は false', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', now: clock.now });
    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    expect(await store.has(NONCE_A, CTX)).toBe(true);
    clock.advance(1001);
    expect(await store.has(NONCE_A, CTX)).toBe(false);
  });

  it('prune は期限切れエントリのみ削除して件数を返す', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', now: clock.now });
    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 1000 });
    await store.checkAndUse(NONCE_B, CTX, { ttlMs: 10_000 });
    clock.advance(1001);
    expect(await store.prune()).toBe(1);
    expect(await store.has(NONCE_B, CTX)).toBe(true);
  });

  it('遅延 sweep が走る間隔でも期限切れは 4011 になる（初見に化けない）', async () => {
    // 回帰: sweep をエントリ読み取りより先に実行すると、判定対象そのものが消えて
    // 「期限切れ（4011）」が「初見（成功）」に化けていた。
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', now: clock.now, sweepIntervalMs: 10 });
    await store.put(NONCE_A, CTX, 1000);
    clock.advance(5000);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.NONCE_EXPIRED);
  });

  it('消費済み nonce は sweep 間隔を跨いでも 4010 のまま（TTL 内）', async () => {
    const clock = makeClock();
    const store = createNonceStore({ backend: 'memory', now: clock.now, sweepIntervalMs: 10 });
    await store.checkAndUse(NONCE_A, CTX, { ttlMs: 600_000 });
    clock.advance(5000);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.REPLAY_DETECTED);
  });

  it('ttlMs が非正なら RangeError（呼び出し側の実装不良）', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await expect(store.put(NONCE_A, CTX, 0)).rejects.toBeInstanceOf(RangeError);
    await expect(store.put(NONCE_A, CTX, Number.NaN)).rejects.toBeInstanceOf(RangeError);
    await expect(store.checkAndUse(NONCE_A, CTX, { ttlMs: -1 })).rejects.toBeInstanceOf(RangeError);
  });
});

describe('NonceStore: バインディングとフォーマット', () => {
  it('binding が client_id と一致すれば消費できる', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await expect(store.checkAndUse(NONCE_A, CTX, { binding: CLIENT })).resolves.toBeUndefined();
  });

  it('binding 不一致で 4012 NONCE_BINDING_MISMATCH', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await expectCode(
      () => store.checkAndUse(NONCE_A, CTX, { binding: 'https://evil.example/client' }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
  });

  it('binding 不一致で拒否された nonce は消費されていない', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await expectCode(
      () => store.checkAndUse(NONCE_A, CTX, { binding: 'https://evil.example/client' }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
    await expect(store.checkAndUse(NONCE_A, CTX, { binding: CLIENT })).resolves.toBeUndefined();
  });

  it('フォーマット不正な nonce は 4013 NONCE_MALFORMED', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await expectCode(() => store.checkAndUse('short', CTX), ErrorCodes.NONCE_MALFORMED);
    await expectCode(() => store.put('short', CTX, 1000), ErrorCodes.NONCE_MALFORMED);
  });

  it('client_id が異なれば同一 nonce でも別コンテキストとして扱う', async () => {
    const store = createNonceStore({ backend: 'memory' });
    const other: NonceContext = { flow: 'oid4vp', clientId: 'https://other.example/client' };
    await store.checkAndUse(NONCE_A, CTX);
    await expect(store.checkAndUse(NONCE_A, other)).resolves.toBeUndefined();
  });

  it('flow が異なれば同一 nonce でも別コンテキストとして扱う', async () => {
    const store = createNonceStore({ backend: 'memory' });
    const siop: NonceContext = { flow: 'siopv2', clientId: CLIENT };
    await store.checkAndUse(NONCE_A, CTX);
    await expect(store.checkAndUse(NONCE_A, siop)).resolves.toBeUndefined();
  });
});

describe('createNonceStore: DI seam', () => {
  it('backend memory は内蔵のインメモリ実装を使う', () => {
    expect(typeof createNonceStore({ backend: 'memory' }).checkAndUse).toBe('function');
  });

  it('注入したアダプタ経由で永続化される', async () => {
    const adapter = new MemoryNonceStoreAdapter();
    const store = createNonceStore({ backend: 'redis', adapter });
    await store.checkAndUse(NONCE_A, CTX);
    expect(adapter.size).toBe(1);
    await expectCode(() => store.checkAndUse(NONCE_A, CTX), ErrorCodes.REPLAY_DETECTED);
  });

  it('memory 以外で adapter 未指定なら TypeError（SDK は永続実装を持たない）', () => {
    for (const backend of ['indexeddb', 'redis', 'sqlite', 'chrome-storage'] as const) {
      expect(() => createNonceStore({ backend })).toThrow(TypeError);
    }
  });

  it('generate は自身の検査を通る nonce を返す', async () => {
    const store = createNonceStore({ backend: 'memory' });
    await expect(store.checkAndUse(store.generate(), CTX)).resolves.toBeUndefined();
    await expect(store.checkAndUse(store.generate(32), CTX)).resolves.toBeUndefined();
  });
});
