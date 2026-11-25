/**
 * `evaluateRefill` の config 既定値が `Object.prototype` 汚染で差し替わらないことの回帰テスト
 *
 * `config` は部分指定が正当な利用法なので、省略したフィールドをプロトタイプ鎖経由で読むと
 * 汚染値が既定値の代わりに採用される。とくに `backoffInitialMs` / `backoffMaxMs` の汚染は
 * 指数バックオフを無効化し、Credential Issuer への補充リクエストを連打させる（fail-open）。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { evaluateRefill } from '../refill.js';
import { BATCH_DEFAULTS, type BatchPoolItem } from '../types.js';

const NOW = 1_000_000;

/** 省略したフィールドへ載せる汚染値（既定値と明確に異なる値を選ぶ）。 */
const POLLUTED = { batchSize: 999_999, refillThreshold: 0, backoffInitialMs: 0, backoffMaxMs: 0 };

/** 有効な未使用 VC を `count` 個持つプールを作る。 */
function pool(count: number): BatchPoolItem[] {
  return Array.from({ length: count }, (_, i) => ({
    id: String(i),
    vc: `vc-${i}`,
    keyHandle: `kp-${i}`,
    used: false,
    expiresAt: NOW + 60_000,
  }));
}

describe('evaluateRefill — Object.prototype 汚染下でも既定値へフォールバックする', () => {
  test('省略した batchSize は汚染値でなく既定値を要求する', () => {
    const d = withPollutedPrototype(POLLUTED, () =>
      evaluateRefill({ pool: [], now: NOW, config: { refillThreshold: 5 } }),
    );
    expect(d.shouldRefill).toBe(true);
    expect(d.requestCount).toBe(BATCH_DEFAULTS.batchSize);
  });

  test('省略した refillThreshold は汚染値でなく既定の閾値で判定する', () => {
    const d = withPollutedPrototype(POLLUTED, () =>
      evaluateRefill({ pool: pool(2), now: NOW, config: { batchSize: 20 } }),
    );
    // 汚染値 0 を拾うと `available >= 0` が常に成立し、補充が永久に立たない。
    expect(d.shouldRefill).toBe(true);
    expect(d.requestCount).toBe(20);
  });

  test('省略した backoffInitialMs は汚染値でなく既定の待機を維持する', () => {
    const d = withPollutedPrototype(POLLUTED, () =>
      evaluateRefill({
        pool: [],
        now: NOW,
        consecutiveFailures: 1,
        lastAttemptAt: NOW,
        config: { refillThreshold: 5 },
      }),
    );
    // 汚染値 0 を拾うとバックオフが消え、失敗直後に補充リクエストを連打する。
    expect(d.shouldRefill).toBe(false);
    expect(d.backoffRemainingMs).toBe(BATCH_DEFAULTS.backoffInitialMs);
  });

  test('省略した backoffMaxMs は汚染値でなく既定の上限でクランプする', () => {
    const d = withPollutedPrototype({ backoffMaxMs: 0 }, () =>
      evaluateRefill({
        pool: [],
        now: NOW,
        consecutiveFailures: 10,
        lastAttemptAt: NOW,
        config: { refillThreshold: 5 },
      }),
    );
    // 汚染値 0 は `Math.min` の上限として効き、待機時間をまるごと 0 へ潰す。
    expect(d.shouldRefill).toBe(false);
    expect(d.backoffRemainingMs).toBe(BATCH_DEFAULTS.backoffMaxMs);
  });
});

describe('evaluateRefill — 汚染下でも明示指定の config は従来どおり効く（正常系）', () => {
  test('明示した refillThreshold / batchSize が優先される', () => {
    const d = withPollutedPrototype(POLLUTED, () =>
      evaluateRefill({ pool: pool(4), now: NOW, config: { refillThreshold: 5, batchSize: 20 } }),
    );
    // 既定の閾値 3 では補充不要な残量 4 でも、明示した閾値 5 で補充が立つ。
    expect(d.shouldRefill).toBe(true);
    expect(d.requestCount).toBe(20);
  });

  test('明示した backoffInitialMs が優先される', () => {
    const d = withPollutedPrototype(POLLUTED, () =>
      evaluateRefill({
        pool: [],
        now: NOW,
        consecutiveFailures: 1,
        lastAttemptAt: NOW,
        config: { backoffInitialMs: 1_000, backoffMaxMs: 10_000 },
      }),
    );
    expect(d.shouldRefill).toBe(false);
    expect(d.backoffRemainingMs).toBe(1_000);
  });
});
