/**
 * `EudiFacade`（`facade.ts`）のメトリクス計装ヘルパ。
 *
 * `did/observability.ts` / `wallet/credential/observability.ts` と同じ理由で、計装のためだけの
 * 補助をファサード本体（既に行数上限近く）から切り出す。高階関数（`with*`）にしているのは、
 * `facade.ts` 側の呼び出し箇所を try/catch/finally なしの 1 式に保つため。
 */

import { MetricNames, type Metrics } from '../../internal/observability/metrics.js';
import { safeEmit } from '../../internal/observability/safe-emit.js';

/**
 * `run` を実行し、成否を `vericerts_pid_issuance_total` へ記録する。
 * 例外は加工せずそのまま再送出する。メトリクス sink の例外は本処理の結果・元の例外を置換しない
 * （`safeEmit`）。
 */
export async function withPidIssuanceMetrics<T>(
  metrics: Metrics,
  run: () => Promise<T>,
): Promise<T> {
  try {
    const result = await run();
    safeEmit(() => metrics.counter(MetricNames.PID_ISSUANCE_TOTAL, { result: 'success' }).inc());
    return result;
  } catch (error) {
    safeEmit(() => metrics.counter(MetricNames.PID_ISSUANCE_TOTAL, { result: 'failure' }).inc());
    throw error;
  }
}

/**
 * `run` を実行し、成否を `vericerts_wua_refresh_total` へ記録する。
 * 例外は加工せずそのまま再送出する。
 */
export async function withWuaRefreshMetrics<T>(
  metrics: Metrics,
  run: () => Promise<T>,
): Promise<T> {
  try {
    const result = await run();
    safeEmit(() => metrics.counter(MetricNames.WUA_REFRESH_TOTAL, { result: 'success' }).inc());
    return result;
  } catch (error) {
    safeEmit(() => metrics.counter(MetricNames.WUA_REFRESH_TOTAL, { result: 'failure' }).inc());
    throw error;
  }
}

/**
 * `run` を実行し、所要時間を秒単位で `vericerts_oid4vp_response_duration_seconds` へ記録する。
 * PID / (Q)EAA はいずれも SD-JWT VC のため `format` は `sd-jwt` 固定。
 * 成否によらず記録する（本メトリクスに `result` ラベルは無い）。
 */
export async function withOid4vpResponseMetrics<T>(
  metrics: Metrics,
  run: () => Promise<T>,
): Promise<T> {
  const startedAt = Date.now();
  try {
    return await run();
  } finally {
    safeEmit(() =>
      metrics
        .histogram(MetricNames.OID4VP_RESPONSE_DURATION_SECONDS, { format: 'sd-jwt' })
        .observe((Date.now() - startedAt) / 1000),
    );
  }
}
