/**
 * `emergencyRevoke` のレシート待機オプション（`maxReceiptAttempts` / `receiptPollIntervalMs`）の入口検証。
 *
 * NaN / 0 / 負値の試行回数だと UserOperation 送信後にレシートを 1 度も問い合わせず `receipt_timeout`（1021）を返し、
 * 失効が成立済みでも呼び出し側が再送して二重に失効を発行しうる。送信**前**に RangeError で fail-closed にする。
 */

import {
  assertNonNegativeFinite,
  assertNonNegativeSafeInteger,
  MAX_TIMER_DELAY_MS,
} from '../primitives/option-guard.js';
import { ownProperty } from '../prototype-safety/own-property.js';

/** レシート未確定時のポーリング回数の既定値。 */
const DEFAULT_MAX_RECEIPT_ATTEMPTS = 10;
/** レシートポーリング間隔（ms）の既定値。 */
const DEFAULT_RECEIPT_POLL_INTERVAL_MS = 1000;

/**
 * 省略時は既定値で埋め、`maxReceiptAttempts`（1 以上の安全な整数）と
 * `receiptPollIntervalMs`（0 以上タイマー上限以下の有限数）を検証して返す。
 *
 * @throws {RangeError} 範囲外・非有限・非数値の場合。
 */
export function resolveReceiptOptions(opts: {
  readonly maxReceiptAttempts?: number;
  readonly receiptPollIntervalMs?: number;
}): { maxReceiptAttempts: number; receiptPollIntervalMs: number } {
  const maxReceiptAttempts = assertNonNegativeSafeInteger(
    'maxReceiptAttempts',
    ownProperty<number>(opts, 'maxReceiptAttempts') ?? DEFAULT_MAX_RECEIPT_ATTEMPTS,
  );
  if (maxReceiptAttempts < 1) {
    throw new RangeError('maxReceiptAttempts は 1 以上の安全な整数である必要があります');
  }
  const receiptPollIntervalMs = assertNonNegativeFinite(
    'receiptPollIntervalMs',
    ownProperty<number>(opts, 'receiptPollIntervalMs') ?? DEFAULT_RECEIPT_POLL_INTERVAL_MS,
  );
  if (receiptPollIntervalMs > MAX_TIMER_DELAY_MS) {
    throw new RangeError(`receiptPollIntervalMs は ${MAX_TIMER_DELAY_MS} 以下である必要があります`);
  }
  return { maxReceiptAttempts, receiptPollIntervalMs };
}
