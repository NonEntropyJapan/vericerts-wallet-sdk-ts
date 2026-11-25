/**
 * did:webvh の `versionTime` 規則。
 *
 * 検証側（`verifyChain`）と生成側（`createDidWebVh` / `updateDidWebVh`）が同じ規則を使うための
 * 共有モジュール。生成側だけ緩いと、署名・公開後に `verifyChain` が DID 全体を拒否する
 * 解決不能なログを作れてしまう。
 *
 * 例外メッセージ・`context` に DID 文字列・Log 本文を含めない。
 */

import { parseIsoDateTimeMs } from '../../../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { nextVersionTime, type WebVhLogEntry } from '../codec.js';

/** 未来判定に許すクロックずれ（5 分）。 */
const VERSION_TIME_CLOCK_SKEW_MS = 5 * 60 * 1000;

/** UTC を明示する末尾（`Z` または `+00:00`）。 */
const UTC_DESIGNATOR = /(?:Z|\+00:00)$/;

/**
 * versionTime（ISO 8601）をエポックミリ秒へ変換する。
 *
 * @param versionTime エントリの `versionTime`、または解決オプションの値。
 * @returns エポックミリ秒。
 * @throws ISO 8601 の日時として解釈できない場合（VericertsError、code `2001`）。
 */
export function parseVersionTime(versionTime: unknown): number {
  const millis = parseIsoDateTimeMs(versionTime);
  if (Number.isNaN(millis)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return millis;
}

/**
 * Log エントリの versionTime が UTC（`Z` / `+00:00`）で、前版より厳密に大きく、かつ未来（現在 + 5 分超）でないことを検証する。
 *
 * 仕様（Read (Resolve) 4）: エントリの versionTime はゾーン指定のないもの・UTC 以外のオフセットを拒否する。
 * 解決オプションの `versionTime`（{@link parseVersionTime}）は対象外で、オフセット付きも受け付ける。
 *
 * @param versionTime 検証対象の versionTime。
 * @param previousMillis 前版の versionTime（エポックミリ秒）。初版は `Number.NEGATIVE_INFINITY`。
 * @param now 現在時刻（エポックミリ秒）。
 * @returns versionTime のエポックミリ秒（次版の `previousMillis` に使う）。
 * @throws 解釈不能・UTC でない・単調増加違反・未来の場合（VericertsError、code `2001`）。
 */
export function assertVersionTimeAdvances(
  versionTime: unknown,
  previousMillis: number,
  now: number,
): number {
  const millis = parseVersionTime(versionTime);
  if (!UTC_DESIGNATOR.test(versionTime as string)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (millis <= previousMillis || millis > now + VERSION_TIME_CLOCK_SKEW_MS) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return millis;
}

/**
 * 追記する次版の `versionTime` を決め、`verifyChain` と同じ規則で検証する。
 *
 * 明示値がなければ呼び出し時刻（前版より進める）を使う。決めた値が単調増加・未来拒否に
 * 反する場合は、署名・公開後に DID 全体が解決不能になるため生成時点で拒否する。
 *
 * @param previous 直前のエントリ（versionTime と parameters.deactivated を参照する）。
 * @param requested 呼び出し側が明示した versionTime（未指定は `undefined`）。
 * @returns 検証済みの versionTime。
 * @throws 前版が失効行・解釈不能・UTC（`Z` / `+00:00`）以外・前版以前・未来の場合（VericertsError、code `2001`）。
 */
export function resolveAppendVersionTime(
  previous: WebVhLogEntry,
  requested: string | undefined,
): string {
  // 失効（`parameters.deactivated`）は不可逆。失効行への追記は `verifyChain` が DID 全体を拒否する。
  // 継承値を拾うと、汚染された Object.prototype で通常更新が拒否される（own のみ読む）。
  if (ownProperty<boolean>(previous.parameters, 'deactivated') === true) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const versionTime = requested ?? nextVersionTime(previous.versionTime);
  assertVersionTimeAdvances(versionTime, parseVersionTime(previous.versionTime), Date.now());
  return versionTime;
}

/**
 * 初版（genesis）の `versionTime` を決め、`verifyChain` の index 0 と同じ規則で検証する。
 *
 * 明示値がなければ呼び出し時刻を使う。解釈不能・未来（現在 + 5 分超）の値は、署名・公開後に
 * DID 全体が解決不能になる上、SCID が `versionTime` を含むため後から直すと DID 自体が変わる。
 * 回復手段がないので生成時点で拒否する。
 *
 * @param requested 呼び出し側が明示した versionTime（未指定は `undefined`）。
 * @returns 検証済みの versionTime。
 * @throws 解釈不能・UTC（`Z` / `+00:00`）以外・未来の場合（VericertsError、code `2001`）。
 */
export function resolveCreateVersionTime(requested: string | undefined): string {
  const versionTime = requested ?? new Date().toISOString();
  assertVersionTimeAdvances(versionTime, Number.NEGATIVE_INFINITY, Date.now());
  return versionTime;
}
