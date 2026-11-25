/**
 * 数値オプションの入口検証（NaN・負値・非整数が比較や `setInterval` に流れて黙って挙動を壊すのを防ぐ）。
 *
 * 型（`number`）では排除できない異常値（`NaN` / `±Infinity` / 負値 / 小数）を、呼び出し側の実装不良として
 * `RangeError`（`assertValidTtl` と同方針）で fail-closed に拒否する。message には値を含めない。
 */

import { type ErrorCode, VericertsError } from '../errors.js';

/** `setInterval` / `setTimeout` が受け付ける遅延の上限（2^31-1 ms）。超過は即時（約 1ms）実行になる。 */
export const MAX_TIMER_DELAY_MS = 2_147_483_647;

/**
 * タイマー間隔として有効な正の有限数（`1 <= value <= {@link MAX_TIMER_DELAY_MS}`）か検査する。
 *
 * @param name オプション名（message 用）。
 * @param value 検査対象。
 * @returns 検証済みの値。
 * @throws `RangeError` 範囲外・非有限・非数値の場合。
 */
export function assertTimerIntervalMs(name: string, value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isFinite(value) ||
    value < 1 ||
    value > MAX_TIMER_DELAY_MS
  ) {
    throw new RangeError(
      `${name} は 1 以上 ${MAX_TIMER_DELAY_MS} 以下の有限数である必要があります`,
    );
  }
  return value;
}

/**
 * 非負の安全整数（件数・カウンタ）か検査する。
 *
 * @param name オプション名（message 用）。
 * @param value 検査対象。
 * @returns 検証済みの値。
 * @throws `RangeError` 負値・小数・非有限・安全整数超過・非数値の場合。
 */
export function assertNonNegativeSafeInteger(name: string, value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} は 0 以上の安全な整数である必要があります`);
  }
  return value;
}

/**
 * 0 以上の有限数（ミリ秒・秒などの非負の量や基準時刻）であることを検証して返す。
 *
 * 比較だけで使う値が `NaN` だと条件が常に偽になり、バックオフ等の待機が黙って無効化される（fail-open）。
 * 入口で弾く。
 *
 * @param name エラーメッセージ用のオプション名。
 * @param value 検査対象。
 * @returns 検証済みの値。
 * @throws {RangeError} 数値でない / 非有限 / 負値。
 */
export function assertNonNegativeFinite(name: string, value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new RangeError(`${name} は 0 以上の有限数である必要があります`);
  }
  return value;
}

/** NumericDate（エポック秒）として扱う上限。`9999-12-31T23:59:59Z`（`Date` / ISO 文字列へ変換できる範囲）。 */
export const MAX_EPOCH_SECONDS = 253_402_300_799;

/**
 * 署名対象の時刻（`iat` / `nbf` 等のエポック秒）として有効か判定する（0 以上 {@link MAX_EPOCH_SECONDS} 以下の有限数）。
 *
 * `NaN` / `±Infinity` / 文字列を JWT に載せると JSON 直列化で `null` や文字列になり、検証不能な署名済みトークンが
 * できる。署名側は呼び出し前に本関数で弾き、呼び出し元の用途に合う `VericertsError` で fail-closed にする。
 *
 * @param value 検査対象。
 * @returns 有効なエポック秒なら `true`。
 */
export function isEpochSeconds(value: unknown): value is number {
  return (
    typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_EPOCH_SECONDS
  );
}

/**
 * 署名対象のエポック秒を検証して返す。不正（{@link isEpochSeconds} を満たさない）なら `code` の VericertsError。
 *
 * @param value 検査対象。
 * @param code 不正時に投げるエラーコード（呼び出し元の用途に合うもの）。
 * @returns 検証済みのエポック秒。
 * @throws {VericertsError} `code`。
 */
export function assertEpochSeconds(value: unknown, code: ErrorCode): number {
  if (!isEpochSeconds(value)) {
    throw new VericertsError(code);
  }
  return value;
}

/**
 * 署名対象の寿命（秒）として有効か判定する。正の有限数で、`nowSeconds + lifetime` が {@link isEpochSeconds} を満たすこと。
 *
 * @param nowSeconds 起点（検証済みのエポック秒）。
 * @param lifetime 検査対象の寿命（秒）。
 * @returns 有効なら `true`（`exp` が `iat` より後になり、日時へ変換できる）。
 */
export function isLifetimeSeconds(nowSeconds: number, lifetime: unknown): lifetime is number {
  return typeof lifetime === 'number' && lifetime > 0 && isEpochSeconds(nowSeconds + lifetime);
}
