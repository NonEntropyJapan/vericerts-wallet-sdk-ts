/**
 * Federation Entity Statement 取得のメトリクス計装。
 *
 * `status-list-observability.ts`（`internal/issuer/`）と同じ理由・同じ形で、`entity-configuration.ts`
 * / `subordinate.ts` の取得フロー本体から計装を切り出す。キャッシュ経路の分類（`cold` /
 * `warm` / `hot`）は `resolveCachedStatement` の既存の観測フック `onCacheEvent` に相乗りして
 * 借りるだけで、ここでは再計算しない（呼び出し側のフックと違う経路が記録される余地を残さない）。
 *
 * 計装は観測に徹し、例外は加工せずそのまま再送出する。entity_id・URL・JWT はラベルにも
 * 載せない。ラベルにはあらかじめ決めた値だけを使う。
 */

import type { CacheState } from '../../../cache/index.js';
import { MetricNames, type Metrics } from '../../../observability/metrics.js';
import { safeEmit } from '../../../observability/safe-emit.js';
import { nonObjectPrototypeProperty } from '../../../prototype-safety/own-property.js';
import type { CachedStatementRequest, FederationCacheDeps } from './statement-cache.js';

/**
 * 取得レイテンシ（`vericerts_federation_statement_fetch_duration_seconds`）の計装を
 * `CachedStatementRequest` に被せる。単位は秒。
 *
 * 計測はキャッシュ参照の直前から始める。終端は経路ごとに異なるため 2 つの包みで出し分ける
 * （`status-list-observability.ts` の `instrumentStatusListFetch` と同じ判断）:
 *
 * - `hot`（TTL 内のエントリ / 記憶済みの取得失敗）はネットワーク I/O を伴わず `fetchJwt` が
 *   呼ばれないため、キャッシュ参照を終えた観測フックの時点が終端になる。
 * - `cold` / `warm` は必ず `fetchJwt` を 1 度だけ呼ぶため、その解決が終端になる。取得失敗も
 *   ネットワーク往復の実測値なので `finally` で成否に依らず記録する。
 *
 * @param metrics ラベル予算を適用したメトリクス。未注入なら `request` をそのまま返す。
 * @param request `resolveCachedStatement` へ渡す予定のリクエスト。
 * @returns 計装済みのリクエスト（`deps.onCacheEvent` / `fetchJwt` を差し替えたもの）。
 */
export function instrumentFederationStatementFetch<T>(
  metrics: Metrics | undefined,
  request: CachedStatementRequest<T>,
): CachedStatementRequest<T> {
  if (metrics === undefined) {
    return request;
  }
  const startedAt = Date.now();
  // 観測フックが必ず先に 1 度だけ呼ばれるため、初期値が記録に使われることはない。
  let cache: CacheState = 'cold';
  const observe = (): void => {
    safeEmit(() =>
      metrics
        .histogram(MetricNames.FEDERATION_STATEMENT_FETCH_DURATION_SECONDS, {
          kind: request.kind,
          cache,
        })
        .observe((Date.now() - startedAt) / 1000),
    );
  };
  return {
    ...request,
    deps: {
      ...request.deps,
      onCacheEvent: (event) => {
        cache = event.state;
        nonObjectPrototypeProperty<FederationCacheDeps['onCacheEvent']>(
          request.deps,
          'onCacheEvent',
        )?.(event);
        if (event.state === 'hot') {
          observe();
        }
      },
    },
    fetchJwt: async () => {
      try {
        return await request.fetchJwt();
      } finally {
        observe();
      }
    },
  };
}
