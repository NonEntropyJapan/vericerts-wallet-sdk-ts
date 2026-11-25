/**
 * 容量退避 / 期限切れ sweep と `checkAndUse` の並行競合の回帰テスト。
 *
 * 以前は退避が古い一覧スナップショットの `usedAt === undefined` だけを根拠に、対象キーのロック無しで
 * `adapter.delete` していたため、並行する `checkAndUse` が書いた使用済み記録を消してリプレイを通した。
 * 1 操作 = 1 往復のアダプタ（redis / sqlite / indexeddb の想定）を仮想時間で再現し、並行起動の位相を
 * 0〜8 ms ずらして（レイテンシも変えて）確認する。実時間には依存しない。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceEvictionReason, NonceStore } from '../../types.js';
import { VirtualClock, VirtualLatencyAdapter } from './virtual-latency-adapter.js';

const CLIENT = 'https://verifier.example/client';
const CTX: NonceContext = { flow: 'oid4vp', clientId: CLIENT };
const TTL = 300_000;
const OFFSETS = [0, 1, 2, 3, 4, 5, 6, 7, 8] as const;
const LATENCIES = [1, 2, 3] as const;

/** 16 バイト相当の base64url nonce（22 文字）。 */
function nonceOf(index: number): string {
  return `${String(index).padStart(2, '0')}IDBAUGBwgJCgsMDQ4PEA`;
}

function expectCode(error: unknown, code: ErrorCode): void {
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(code);
}

/** reject を値として受け取る（`undefined` = 受理）。 */
async function outcome(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return error;
  }
}

interface Rig {
  readonly clock: VirtualClock;
  readonly store: NonceStore;
  readonly wall: { now: number };
  readonly evicted: NonceEvictionReason[];
}

function makeRig(
  latencyMs: number,
  opts: { bloomFilter?: boolean; maxEntries?: number; deleteLatencyMs?: number } = {},
): Rig {
  const clock = new VirtualClock();
  const wall = { now: 1_700_000_000_000 };
  const evicted: NonceEvictionReason[] = [];
  const store = createNonceStore({
    backend: 'memory',
    adapter: new VirtualLatencyAdapter(clock, latencyMs, opts.deleteLatencyMs),
    maxEntries: opts.maxEntries ?? 3,
    bloomFilter: opts.bloomFilter,
    now: () => wall.now,
    onEvict: (_entry, reason) => {
      evicted.push(reason);
    },
  });
  return { clock, store, wall, evicted };
}

/** 仮想時間を最後まで進めて、`put` の連続発行を完了させる。 */
async function fill(rig: Rig, count: number, ttlMs = TTL): Promise<void> {
  for (let i = 0; i < count; i += 1) {
    const pending = rig.store.put(nonceOf(i), CTX, ttlMs);
    await rig.clock.runAll();
    await pending;
  }
}

describe('LRU 退避と checkAndUse の並行競合', () => {
  for (const latency of LATENCIES) {
    for (const offset of OFFSETS) {
      it(`満杯への put（退避）と未使用 nonce の checkAndUse が重なっても 2 回目は 4010（latency=${latency}ms, 位相=${offset}ms）`, async () => {
        const rig = makeRig(latency);
        await fill(rig, 3);

        const flood = outcome(rig.store.put(nonceOf(3), CTX, TTL));
        await rig.clock.advance(offset);
        const use = outcome(rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT }));
        await rig.clock.runAll();

        expect(await flood).toBeUndefined();
        // 正規の 1 回目は（退避に勝っても負けても）受理される。
        expect(await use).toBeUndefined();
        // 使用済み記録が退避で失われていれば、ここが「初見」として受理されてしまう。
        const second = outcome(rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT }));
        await rig.clock.runAll();
        expectCode(await second, ErrorCodes.REPLAY_DETECTED);
        const recorded = rig.store.has(nonceOf(0), CTX);
        await rig.clock.runAll();
        expect(await recorded).toBe(true);
      });
    }
  }

  it('使用済みエントリは、退避が候補にしても（再読込で使用済みと分かり）削除されない', async () => {
    const rig = makeRig(2, { maxEntries: 4 });
    await fill(rig, 3);
    const used = rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT });
    await rig.clock.runAll();
    await used;

    // 退避フラッド: 未使用（N1 / N2）だけが退避対象になり、使用済み N0 は残り続ける。
    for (let i = 3; i < 10; i += 1) {
      const pending = outcome(rig.store.put(nonceOf(i), CTX, TTL));
      await rig.clock.runAll();
      expect(await pending).toBeUndefined();
    }
    const recorded = rig.store.has(nonceOf(0), CTX);
    await rig.clock.runAll();
    expect(await recorded).toBe(true);
    const replay = outcome(rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT }));
    await rig.clock.runAll();
    expectCode(await replay, ErrorCodes.REPLAY_DETECTED);
  });

  for (const offset of OFFSETS) {
    it(`満杯への put が並行しても互いの退避候補のロックを待ち合わず（デッドロックせず）全て完了する（位相=${offset}ms）`, async () => {
      const rig = makeRig(2, { maxEntries: 4 });
      await fill(rig, 4);
      const first = outcome(rig.store.put(nonceOf(4), CTX, TTL));
      await rig.clock.advance(offset);
      const second = outcome(rig.store.put(nonceOf(5), CTX, TTL));
      const third = outcome(rig.store.checkAndUse(nonceOf(1), CTX, { binding: CLIENT }));
      await rig.clock.runAll();

      expect(await first).toBeUndefined();
      expect(await second).toBeUndefined();
      expect(await third).toBeUndefined();
      const replay = outcome(rig.store.checkAndUse(nonceOf(1), CTX, { binding: CLIENT }));
      await rig.clock.runAll();
      expectCode(await replay, ErrorCodes.REPLAY_DETECTED);
    });
  }
});

describe('期限切れ退避 / prune と「再発行→使用」の並行競合', () => {
  /** E0 を期限切れにしたストアを作る（E1 / E2 は未失効、容量 3）。 */
  async function expiredRig(latency: number): Promise<Rig> {
    // 削除の着弾を遅らせ、スナップショットから削除までの窓に「再発行 → 使用」が収まるようにする。
    const rig = makeRig(latency, { deleteLatencyMs: 24 });
    const first = rig.store.put(nonceOf(0), CTX, 1_000);
    await rig.clock.runAll();
    await first;
    for (const i of [1, 2]) {
      const pending = rig.store.put(nonceOf(i), CTX, TTL);
      await rig.clock.runAll();
      await pending;
    }
    rig.wall.now += 1_001;
    return rig;
  }

  /** 期限切れ E0 を再発行して 1 回使う並行タスク（位相ずらし後に開始）。 */
  async function reissueAndUse(rig: Rig, offset: number): Promise<unknown> {
    await rig.clock.sleep(offset);
    expect(await outcome(rig.store.put(nonceOf(0), CTX, TTL))).toBeUndefined();
    return await outcome(rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT }));
  }

  for (const latency of LATENCIES) {
    for (const offset of OFFSETS) {
      it(`容量退避の期限切れ削除が再発行・使用済み記録を消さない（latency=${latency}ms, 位相=${offset}ms）`, async () => {
        const rig = await expiredRig(latency);
        const flood = outcome(rig.store.put(nonceOf(3), CTX, TTL));
        const reissue = reissueAndUse(rig, offset);
        await rig.clock.runAll();

        expect(await flood).toBeUndefined();
        expect(await reissue).toBeUndefined();
        const second = outcome(rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT }));
        await rig.clock.runAll();
        expectCode(await second, ErrorCodes.REPLAY_DETECTED);
      });

      it(`prune の期限切れ削除が再発行・使用済み記録を消さない（latency=${latency}ms, 位相=${offset}ms）`, async () => {
        const rig = await expiredRig(latency);
        const pruning = outcome(rig.store.prune());
        const reissue = reissueAndUse(rig, offset);
        await rig.clock.runAll();

        expect(await pruning).toBeUndefined();
        expect(await reissue).toBeUndefined();
        const second = outcome(rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT }));
        await rig.clock.runAll();
        expectCode(await second, ErrorCodes.REPLAY_DETECTED);
      });
    }
  }

  it('prune は削除時点で期限切れのエントリだけを数え、onEvict に最新のエントリで通知する', async () => {
    const rig = await expiredRig(2);
    const pruning = rig.store.prune();
    await rig.clock.runAll();
    expect(await pruning).toBe(1);
    expect(rig.evicted).toEqual(['expired']);
  });
});

describe('同一 nonce の並行 checkAndUse（Bloom 復元込み）', () => {
  for (const offset of OFFSETS) {
    it(`ちょうど 1 回だけ受理される（位相=${offset}ms）`, async () => {
      const rig = makeRig(2, { bloomFilter: true, maxEntries: 10 });
      const first = outcome(rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT }));
      await rig.clock.advance(offset);
      const second = outcome(rig.store.checkAndUse(nonceOf(0), CTX, { binding: CLIENT }));
      await rig.clock.runAll();

      expect(await first).toBeUndefined();
      expectCode(await second, ErrorCodes.REPLAY_DETECTED);
    });
  }
});
