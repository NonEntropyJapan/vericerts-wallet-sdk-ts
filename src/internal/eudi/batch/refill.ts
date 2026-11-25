/**
 * Batch プールの自動補充判定。
 *
 * 有効な未使用 VC の残量が補充閾値を下回ったら補充を要求する。補充失敗時は
 * 指数バックオフ（既定 5min → 1h）で再試行間隔を広げ、残量 0 でユーザー通知の
 * 判断材料（`depleted`）を返す。
 *
 * 本モジュールは判定のみを行う純粋関数。実際の Token / Credential リクエストや
 * バックオフのスケジューリングは呼び出し側 facade が担う。
 */

import {
  assertNonNegativeFinite,
  assertNonNegativeSafeInteger,
} from '../../primitives/option-guard.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { countAvailable } from './pool.js';
import {
  BATCH_DEFAULTS,
  type RefillConfig,
  type RefillDecision,
  type RefillInput,
} from './types.js';

/**
 * 部分指定の config を既定値で埋める。
 *
 * 各項目は自身のプロパティに限って読む。省略は正当な利用法なので、継承値を拾うと
 * `Object.prototype` 汚染下で既定値が差し替わり、`backoffInitialMs` / `backoffMaxMs` を 0 に
 * 潰してバックオフを無効化する（Credential Issuer へのリクエスト連打, fail-open）。
 */
function resolveConfig(partial: RefillConfig | Partial<RefillConfig> | undefined): RefillConfig {
  const source = partial ?? {};
  // NaN / 負値 / 非有限はバックオフ比較を常に偽にして補充を連打させる（fail-open）ため RangeError。
  return {
    batchSize: assertNonNegativeSafeInteger(
      'batchSize',
      ownProperty<number>(source, 'batchSize') ?? BATCH_DEFAULTS.batchSize,
    ),
    refillThreshold: assertNonNegativeSafeInteger(
      'refillThreshold',
      ownProperty<number>(source, 'refillThreshold') ?? BATCH_DEFAULTS.refillThreshold,
    ),
    backoffInitialMs: assertNonNegativeFinite(
      'backoffInitialMs',
      ownProperty<number>(source, 'backoffInitialMs') ?? BATCH_DEFAULTS.backoffInitialMs,
    ),
    backoffMaxMs: assertNonNegativeFinite(
      'backoffMaxMs',
      ownProperty<number>(source, 'backoffMaxMs') ?? BATCH_DEFAULTS.backoffMaxMs,
    ),
  };
}

/**
 * 連続失敗回数に対する指数バックオフ待機時間（ミリ秒）を算出する。
 *
 * `failures=0`（未失敗）は 0 を返す。`failures>=1` で
 * `initial * 2^(failures-1)` を `max` で上限クランプする（5min, 10min, 20min, ... → 1h）。
 */
function backoffDelayMs(failures: number, config: RefillConfig): number {
  if (failures <= 0) {
    return 0;
  }
  const scaled = config.backoffInitialMs * 2 ** (failures - 1);
  return Math.min(scaled, config.backoffMaxMs);
}

/**
 * 自動補充が必要かを判定する。
 *
 * 判定順:
 * 1. 有効な未使用 VC 残量 `available` を数える（期限切れは除外）。
 * 2. `available >= refillThreshold` なら補充不要。
 * 3. 閾値未満でも、直近の失敗によるバックオフ待機中（`now - lastAttemptAt < backoff`）
 *    なら今回は補充を見送り、残待機時間を `backoffRemainingMs` で返す。
 * 4. それ以外は補充対象。`requestCount = batchSize` を要求する。
 *
 * `depleted`（残量 0）は補充可否と独立に返し、呼び出し側のユーザー通知判断に使う。
 *
 * @param input プール・基準時刻・失敗回数・前回試行時刻・設定。
 * @returns 補充判定結果。
 * @throws {RangeError} `now` / `lastAttemptAt` / config / `consecutiveFailures` が非有限・負値・非整数の場合
 *         （バックオフを無効化して補充を連打しないよう fail-closed）。
 */
export function evaluateRefill(input: RefillInput): RefillDecision {
  const config = resolveConfig(ownProperty<Partial<RefillConfig>>(input, 'config'));
  assertNonNegativeFinite('now', input.now);
  const failures = assertNonNegativeSafeInteger(
    'consecutiveFailures',
    ownProperty<number>(input, 'consecutiveFailures') ?? 0,
  );
  const rawLastAttemptAt = ownProperty<number>(input, 'lastAttemptAt');
  const lastAttemptAt =
    rawLastAttemptAt === undefined
      ? undefined
      : assertNonNegativeFinite('lastAttemptAt', rawLastAttemptAt);
  const available = countAvailable(input.pool, input.now);
  const depleted = available === 0;

  if (available >= config.refillThreshold) {
    return {
      shouldRefill: false,
      available,
      requestCount: 0,
      depleted,
      backoffRemainingMs: 0,
    };
  }

  const delay = backoffDelayMs(failures, config);
  if (delay > 0 && lastAttemptAt !== undefined) {
    const elapsed = input.now - lastAttemptAt;
    const remaining = delay - elapsed;
    if (remaining > 0) {
      return {
        shouldRefill: false,
        available,
        requestCount: 0,
        depleted,
        backoffRemainingMs: remaining,
      };
    }
  }

  return {
    shouldRefill: true,
    available,
    requestCount: config.batchSize,
    depleted,
    backoffRemainingMs: 0,
  };
}
