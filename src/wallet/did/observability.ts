/**
 * `did.resolve` のメトリクスを記録する。
 *
 * 「解決の観測結果をどの系列へ積むか」を `resolve.ts` の計装本体から切り出す。メソッド名の
 * 算出は行わない — ログ属性 `did_method`・Span 属性 `did.method`・本ラベル `method` は
 * `resolve.ts` の `didMethod` 1 箇所から作り、同じ解決に違うメソッド名が付く余地を残さない。
 */

import { MetricNames, type Metrics } from '../../internal/observability/metrics.js';

/**
 * DID 解決の回数を成否別に数え、所要時間を秒単位でヒストグラムに記録する。
 *
 * Resolver がキャッシュのヒットをこの計装に通知しないため、所要時間の `cache` ラベルは常に `cold`。
 *
 * @param method DID メソッド名。形式不正の入力（`undefined`）は `other` にまとめる。
 */
export function recordDidResolveMetrics(
  metrics: Metrics,
  method: string | undefined,
  result: 'success' | 'failure',
  durationMs: number,
): void {
  const label = method ?? 'other';
  metrics.counter(MetricNames.DID_RESOLVE_TOTAL, { method: label, result }).inc();
  metrics
    .histogram(MetricNames.DID_RESOLVE_DURATION_SECONDS, { method: label, cache: 'cold' })
    .observe(durationMs / 1000);
}
