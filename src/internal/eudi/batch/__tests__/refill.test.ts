/**
 * 自動補充判定テスト。
 *
 * evaluateRefill 単体テストに加え、Batch ライフサイクル（発行 → 連続消費 →
 * 閾値割れで補充判定 → パージ）を通した統合テストを含む。
 */

import { describe, expect, test } from 'bun:test';
import { consumeCredential, purgeExpired } from '../pool.js';
import { evaluateRefill } from '../refill.js';
import { BATCH_DEFAULTS, type BatchPoolItem } from '../types.js';

const NOW = 1_000_000;

function item(id: string, overrides: Partial<BatchPoolItem> = {}): BatchPoolItem {
  return {
    id,
    vc: `vc-${id}`,
    keyHandle: `kp-${id}`,
    used: false,
    expiresAt: NOW + 60_000,
    ...overrides,
  };
}

function pool(count: number): BatchPoolItem[] {
  return Array.from({ length: count }, (_, i) => item(String(i)));
}

describe('evaluateRefill — 閾値判定', () => {
  test('残量 >= 閾値なら補充不要', () => {
    const d = evaluateRefill({ pool: pool(3), now: NOW });
    expect(d.shouldRefill).toBe(false);
    expect(d.available).toBe(3);
    expect(d.requestCount).toBe(0);
    expect(d.depleted).toBe(false);
  });

  test('残量 < 閾値なら batchSize 個の補充を要求する', () => {
    const d = evaluateRefill({ pool: pool(2), now: NOW });
    expect(d.shouldRefill).toBe(true);
    expect(d.requestCount).toBe(BATCH_DEFAULTS.batchSize);
  });

  test('期限切れ・使用済みは残量に数えない', () => {
    const p = [item('a'), item('b', { used: true }), item('c', { expiresAt: NOW - 1 })];
    const d = evaluateRefill({ pool: p, now: NOW });
    expect(d.available).toBe(1);
    expect(d.shouldRefill).toBe(true);
  });

  test('残量 0 で depleted=true', () => {
    const d = evaluateRefill({ pool: [], now: NOW });
    expect(d.depleted).toBe(true);
    expect(d.shouldRefill).toBe(true);
  });

  test('config 上書き（閾値・バッチサイズ）が効く', () => {
    const d = evaluateRefill({
      pool: pool(4),
      now: NOW,
      config: { refillThreshold: 5, batchSize: 20 },
    });
    expect(d.shouldRefill).toBe(true);
    expect(d.requestCount).toBe(20);
  });
});

describe('evaluateRefill — 指数バックオフ（補充失敗時）', () => {
  test('失敗 1 回・初期待機内なら補充を見送り残待機を返す', () => {
    const d = evaluateRefill({
      pool: pool(1),
      now: NOW,
      consecutiveFailures: 1,
      lastAttemptAt: NOW - 60_000, // 1min 経過 < 5min
    });
    expect(d.shouldRefill).toBe(false);
    expect(d.backoffRemainingMs).toBe(BATCH_DEFAULTS.backoffInitialMs - 60_000);
  });

  test('失敗後でも待機経過後は補充を再開する', () => {
    const d = evaluateRefill({
      pool: pool(1),
      now: NOW,
      consecutiveFailures: 1,
      lastAttemptAt: NOW - BATCH_DEFAULTS.backoffInitialMs - 1,
    });
    expect(d.shouldRefill).toBe(true);
    expect(d.backoffRemainingMs).toBe(0);
  });

  test('待機は最大値（1h）でクランプされる', () => {
    const d = evaluateRefill({
      pool: [],
      now: NOW,
      consecutiveFailures: 10, // 5min * 2^9 は 1h を超える
      lastAttemptAt: NOW,
    });
    expect(d.backoffRemainingMs).toBe(BATCH_DEFAULTS.backoffMaxMs);
  });

  test('失敗 0 回はバックオフなしで即補充', () => {
    const d = evaluateRefill({
      pool: pool(1),
      now: NOW,
      consecutiveFailures: 0,
      lastAttemptAt: NOW,
    });
    expect(d.shouldRefill).toBe(true);
  });
});

describe('統合: Batch ライフサイクル（発行 → 消費 → 補充判定 → パージ）', () => {
  test('N=10 を発行し閾値まで消費すると補充判定が立つ', () => {
    let current: readonly BatchPoolItem[] = pool(BATCH_DEFAULTS.batchSize);

    // 補充閾値到達直前まで消費（10 → 3 まで 7 個消費）。
    for (let i = 0; i < 7; i += 1) {
      const r = consumeCredential(current, NOW, `rp-${i}`);
      expect(r.consumed).toBe(true);
      current = r.pool;
    }
    let decision = evaluateRefill({ pool: current, now: NOW });
    expect(decision.available).toBe(3);
    expect(decision.shouldRefill).toBe(false);

    // もう 1 個消費して残量 2 → 閾値割れ → 補充判定。
    const r = consumeCredential(current, NOW, 'rp-7');
    current = r.pool;
    decision = evaluateRefill({ pool: current, now: NOW });
    expect(decision.available).toBe(2);
    expect(decision.shouldRefill).toBe(true);
    expect(decision.requestCount).toBe(BATCH_DEFAULTS.batchSize);
  });

  test('消費済みが期限切れになったらパージで鍵ハンドルを回収する', () => {
    let current: readonly BatchPoolItem[] = pool(2);
    const consumed = consumeCredential(current, NOW, 'rp');
    current = consumed.pool;

    // 全 VC が期限切れ後にパージ。
    const later = NOW + 120_000;
    const purged = purgeExpired(current, later);
    expect(purged.pool).toHaveLength(0);
    expect(purged.removedKeyHandles).toHaveLength(2);

    // パージ後は残量 0・depleted で補充判定。
    const decision = evaluateRefill({ pool: purged.pool, now: later });
    expect(decision.depleted).toBe(true);
    expect(decision.shouldRefill).toBe(true);
  });
});

describe('evaluateRefill — 非有限入力でバックオフを無効化しない', () => {
  const baseline = {
    pool: pool(0),
    now: NOW,
    consecutiveFailures: 3,
    lastAttemptAt: NOW - 1000,
  };

  test('ベースライン: 3 連続失敗・直近試行 1 秒前は待機中', () => {
    const d = evaluateRefill(baseline);
    expect(d.shouldRefill).toBe(false);
    expect(d.backoffRemainingMs).toBeGreaterThan(0);
  });

  test('config の NaN / 負値 / 非整数 / 文字列は RangeError', () => {
    for (const config of [
      { backoffInitialMs: Number.NaN },
      { backoffInitialMs: -1 },
      { backoffMaxMs: Number.NaN },
      { backoffMaxMs: Number.POSITIVE_INFINITY },
      { batchSize: Number.NaN },
      { batchSize: -5 },
      { batchSize: 1.5 },
      { refillThreshold: Number.NaN },
      { batchSize: '10' as unknown as number },
    ]) {
      expect(() => evaluateRefill({ ...baseline, config })).toThrow(RangeError);
    }
  });

  test('now / lastAttemptAt / consecutiveFailures の非有限・負値は RangeError', () => {
    for (const override of [
      { now: Number.NaN },
      { now: Number.POSITIVE_INFINITY },
      { lastAttemptAt: Number.NaN },
      { lastAttemptAt: Number.NEGATIVE_INFINITY },
      { lastAttemptAt: -1 },
      { consecutiveFailures: Number.NaN },
      { consecutiveFailures: -1 },
      { consecutiveFailures: 1.5 },
    ]) {
      expect(() => evaluateRefill({ ...baseline, ...override })).toThrow(RangeError);
    }
  });
});
