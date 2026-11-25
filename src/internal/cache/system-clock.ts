/**
 * 実時計（エポック秒）の SSOT。
 *
 * `() => Math.floor(Date.now() / 1000)` という 1 行の純粋関数だが、`did-web-cache.ts` /
 * `status-list-cache.ts` / `entity-cache.ts` / `statement-cache.ts` / `etsi-tsl/cache.ts` /
 * `rp-access/cache.ts` の 6 ファイルに実質同一の private 実装が個別に存在し、各キャッシュ層の
 * TTL キャッシュ生成 (`createXxxCache`) の `nowSeconds` 既定値として使われていた。将来どこか
 * 1 箇所だけ変更（例: `Date.now()` をモック可能な時計 abstraction に差し替える等）すると残りが
 * 追随せず挙動が乖離するため、`internal/cache/` 配下（対象非依存の TTL キャッシュ実装が置かれて
 * いる場所）へ集約する。
 *
 * 注入された時刻の有限性検査（`assertFiniteClock`）も同じ「時計」の関心事としてここに置く。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

/** 実時計（エポック秒）。 */
export function systemNowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * 呼び出し側が注入した現在時刻（`nowSeconds` / `nowMs` など）が有限数であることを検査する。
 *
 * `NaN` / `±Infinity` の時計は `now >= exp` / `now < nbf` / `iat > now + skew` のような比較を
 * すべて `false`（または常に一方向）にし、期限切れ・未発効・未来 `iat`・リプレイを素通しする
 * fail-open になる。型（`number`）では排除できないため、時刻比較の入口で fail-closed に拒否する
 * （`isTrustedIssuer` / `evaluateTimeClaims`）。
 *
 * 例外は時刻オプション不正用の `4015 CLOCK_SKEW_OPTION_INVALID`（message / context に値を含めない）。
 *
 * @param now 注入された現在時刻（単位は呼び出し側に依存。判定は有限性のみ）。
 * @returns 有限数の `now`（呼び出し側での代入用）。
 * @throws `now` が有限数でない場合（VericertsError、code `4015`）。
 */
export function assertFiniteClock(now: number): number {
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new VericertsError(ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
  }
  return now;
}
