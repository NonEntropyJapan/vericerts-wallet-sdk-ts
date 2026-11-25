/**
 * `options.nowSeconds` の型不正・非有限・非整数値・値域外に対する防御的検証の回帰テスト
 * （値域チェックは）。
 *
 * `?? systemNowSeconds()` は `null` / `undefined` しか拾わないため、`NaN` / 文字列などの型不正値が
 * そのまま下流に流れていた。影響は二つ:
 *
 * - fail-open の対象拡大: `readTrustedListCache` の失効判定（`ttl-cache.ts` の
 *   `now >= entry.expiresAtSeconds`）が `NaN >= x` で常に `false` になり、期限切れキャッシュを
 *   「有効期限内」と誤判定して FO-5 を不当に成立させる。
 * - 成功パスのクラッシュ: 取得成功時の `new Date(nowSeconds * 1000).toISOString()`（キャッシュ
 *   格納）が非有限値で生の `RangeError` を投げる（同じ型変換の問題）。加えて、有限だが
 *   非整数（例 `1.5`）だと `storeTrustedListCache` の TTL 計算が非整数になり、`ttl-cache.ts` の
 *   `assertTtlSeconds` が `VericertsError(VC_SCHEMA_INVALID)` を投げてクラッシュする（同じ
 *   バグクラスの別経路）。
 *
 * `1e13` や `-1e13` のような値は `Number.isInteger` を通過するが `Date` が扱える
 * 値域（エポック秒として 0 〜 `8_640_000_000_000`）の外にあり、成功パスの生 `RangeError` を
 * 引き起こす。負値（`-1e13` や `-1`）はさらに、`ttl-cache.ts` の `now >= expiresAtSeconds` を
 * 常に `false` にして期限切れキャッシュを「有効期限内」と誤判定し、FO-5 を不当に成立させる。
 *
 * ただし値域チェック（下限 0）はこの FO-5 の誤判定そのものを塞ぐものではない点に注意する。
 * `nowSeconds: 0` のような値域内の過去時刻を渡されても同じ誤判定は起こり得る（呼び出し元は
 * 任意の過去時刻を渡せるため、この誤判定は値域チェックでは原理的に塞げない）。値域チェックが
 * 実際に塞ぐのは、値域外による生の `RangeError` と、エポック秒として正当なユースケースが無い
 * 明白に不正な負値のみである。
 *
 * `etsi-tsl.ts` の `resolveNowSeconds`（`now-seconds.ts`）は `Number.isInteger` に加えて値域も
 * 検証し、型不正・非有限・非整数値については両方の経路（成功パスの生 `RangeError`・期限切れ
 * キャッシュの誤判定）を実時計へのフォールバックで防ぐ。実時計（テスト実行時点、2026 年以降）は
 * 本ファイルの `NOW_SECONDS`（2023 年相当）より確実に後なので、フォールバックが効いていれば
 * 「期限切れ」と正しく判定される。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { loadTrustedList } from '../../etsi-tsl.js';
import { expectRejectCode, failOpenHarness, primedAndOffline, TSL_URL } from './harness.js';

/** 型不正・非有限・非整数・値域外な `nowSeconds`(実時計へフォールバックすべき値)。 */
const INVALID_NOW_SECONDS: ReadonlyArray<[string, unknown]> = [
  ['NaN', Number.NaN],
  ["型不正(文字列 'x')", 'x'],
  ['Infinity', Number.POSITIVE_INFINITY],
  ['1.5(非整数)', 1.5],
  ['1e13(Date が扱える値域の上限超過)', 1e13],
  ['8_640_000_000_001(Date が扱える値域の上限を1超過)', 8_640_000_000_001],
  ['-1e13(大きな負値)', -1e13],
  ['-1(負値)', -1],
];

/** 実時計より確実に未来のエポック秒（2233 年相当）。 */
const FAR_FUTURE_SECONDS = 8_000_000_000;

describe('nowSeconds の型不正・非有限・非整数値・値域外値に対する防御', () => {
  it.each(
    INVALID_NOW_SECONDS,
  )('取得成功時に nowSeconds(%s) を渡してもクラッシュしない(成功パスのクラッシュ防止)', async (_label, nowSeconds) => {
    // 実時計へフォールバックしても NextUpdate 内（取得結果の期限切れ拒否に当たらない）ようにする。
    const h = failOpenHarness(FAR_FUTURE_SECONDS);
    const result = await loadTrustedList(TSL_URL, {
      ...h.base,
      nowSeconds: nowSeconds as never,
    });
    expect(result.serviceCertificates.length).toBe(1);
  });

  it.each(
    INVALID_NOW_SECONDS,
  )('nowSeconds(%s) は実時計にフォールバックし、期限切れキャッシュを有効期限内と誤判定しない', async (_label, nowSeconds) => {
    // 有効なフェイク時計で一度取得・格納したのち、フェイク時計上はまだ NextUpdate 内という
    // 状態を作る。ここで不正な nowSeconds を渡したとき、取り違えで「有効期限内」と誤判定
    // されれば FO-5 が成立してしまう。実時計(テスト実行時点)はフェイク時計の NextUpdate
    // よりずっと後なので、正しくフォールバックしていれば期限切れとして fail-closed になる。
    const h = await primedAndOffline(loadTrustedList);
    await expectRejectCode(
      loadTrustedList(TSL_URL, {
        ...h.base,
        nowSeconds: nowSeconds as never,
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.TSL_FETCH_FAILED,
    );
    // 監査記録も残らない(`resolveFailOpen` 自体を呼ばない経路)。
    expect(h.records).toEqual([]);
  });
});
