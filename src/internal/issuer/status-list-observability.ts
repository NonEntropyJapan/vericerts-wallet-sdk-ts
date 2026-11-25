/**
 * Status List 解決のメトリクス計装。
 *
 * 「どの観測点でどの系列へ積むか」を `status-list-resolver.ts` の検証フロー本体から切り出す。
 * `status-list-fail-open.ts` と同じく、解決器本体の行数上限を圧迫せずに計装の根拠を残すためである。
 *
 * 本モジュールは**判断を持たない**。キャッシュ経路の分類（`cold`、`warm`、`hot`）は
 * `lookupCachedToken` が唯一の判断点であり、ここは既存の観測フック `onCacheEvent` に相乗りして
 * その分類を借りるだけにする。分類をここで再計算すると、同じ取得について呼び出し側のフックと
 * メトリクスで違う経路が記録される余地が残るためである。
 *
 * 計装は観測に徹し、例外は加工せずそのまま再送出する。URI・インデックス・Token はラベルにも
 * 載せない。ラベルにはあらかじめ決めた値だけを使う。
 */

import type { CacheState } from '../cache/index.js';
import type { StatusCheckResult, StatusListResolver } from '../credential/sdjwt/status.js';
import { MetricNames, type Metrics } from '../observability/metrics.js';
import { safeEmit } from '../observability/safe-emit.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import type { StatusListCacheDeps, StatusListTokenResponse } from './status-list-cache.js';

/** Status List Token を URI から取得する関数（`StatusListResolverOptions.fetchToken`）。 */
type FetchToken = (uri: string) => Promise<string | StatusListTokenResponse>;

/** 取得フェーズ 1 回分の計装（差し替え済みのキャッシュ依存と取得関数）。 */
export interface StatusListFetchProbe {
  /** `lookupCachedToken` へ渡すキャッシュ依存（キャッシュ状態を借りるフックを被せたもの）。 */
  readonly deps: StatusListCacheDeps;
  /** ネットワーク取得。成否に関わらず所要時間を記録する。 */
  readonly fetchToken: FetchToken;
}

/**
 * 取得レイテンシ（`vericerts_status_list_fetch_duration_seconds`）の計装を組み立てる。
 * 単位は秒。
 *
 * 計測はキャッシュ参照の直前から始める。終端は経路ごとに異なるため 2 つの包みで出し分ける:
 *
 * - `hot`（TTL 内のエントリ / 記憶済みの取得失敗）はネットワーク I/O を伴わず `fetchToken` が
 *   呼ばれないため、キャッシュ参照を終えた観測フックの時点が終端になる。
 * - `cold` / `warm` は必ず `fetchToken` を 1 度だけ呼ぶため、その解決が終端になる。取得失敗も
 *   ネットワーク往復の実測値なので `finally` で成否に依らず記録する。
 *
 * 取得に続く Fail-open 判定は同意プロンプトで人間の応答を待ち得るので、意図的に含めない
 * （含めると `cold` / `warm` のヒストグラムがネットワーク往復の分布として読めなくなる）。
 *
 * `resolve` の呼び出しごとに新しい計装を作るため、並行する解決がキャッシュ状態を取り違えることは
 * ない（状態を共有するのは 1 回分の取得フェーズだけ）。
 *
 * @param metrics ラベル予算を適用したメトリクス。未注入なら素の依存をそのまま返す。
 * @param deps 解決器が持つキャッシュ依存。呼び出し側の `onCacheEvent` はそのまま転送する。
 * @param fetchToken 解決器が持つ取得関数。
 * @returns 差し替え済みのキャッシュ依存と取得関数。
 */
export function instrumentStatusListFetch(
  metrics: Metrics | undefined,
  deps: StatusListCacheDeps,
  fetchToken: FetchToken,
): StatusListFetchProbe {
  if (metrics === undefined) {
    return { deps, fetchToken };
  }
  const startedAt = Date.now();
  const onCacheEvent = nonObjectPrototypeProperty<StatusListCacheDeps['onCacheEvent']>(
    deps,
    'onCacheEvent',
  );
  // 観測フックが必ず先に 1 度だけ呼ばれるため、初期値が記録に使われることはない。
  let cache: CacheState = 'cold';
  const observe = (): void => {
    safeEmit(() =>
      metrics
        .histogram(MetricNames.STATUS_LIST_FETCH_DURATION_SECONDS, { cache })
        .observe((Date.now() - startedAt) / 1000),
    );
  };
  return {
    deps: {
      ...deps,
      onCacheEvent: (event) => {
        cache = event.state;
        onCacheEvent?.(event);
        if (event.state === 'hot') {
          observe();
        }
      },
    },
    fetchToken: async (uri) => {
      try {
        return await fetchToken(uri);
      } finally {
        observe();
      }
    },
  };
}

/**
 * 判定の成否（`vericerts_status_list_check_total` の `result` ラベル）を結果から見分ける。
 *
 * FO-1 は Status List を一度も読めていない（返る `value` は既定値であって
 * 読み取ったビットではない）ため、通過していても「失効確認ができた」とは数えない。stale な実データを
 * 検証して実際のビット値を返す FO-2 は確認が成立しているので `success` に数える。
 */
function checkResult(result: StatusCheckResult): 'success' | 'failure' {
  const failedOpen =
    ownProperty<StatusCheckResult['warnings']>(result, 'warnings')?.some(
      (warning) => warning.policyEvent === 'FO-1',
    ) === true;
  return failedOpen ? 'failure' : 'success';
}

/**
 * 判定回数（`vericerts_status_list_check_total`）を数える包みを被せる。
 *
 * 数えるのは**失効確認ができたか**であって VC が有効だったかではない。失効済み（ビット値が 0 以外）
 * でも確認自体は成立しているため `success` である。`failure` になるのは、取得・署名検証・`sub` 一致
 * 確認・ビット読取りのいずれかが送出した場合と、FO-1 で確認を諦めた場合に限る。
 *
 * @param resolver 計装対象の解決器。
 * @param metrics ラベル予算を適用したメトリクス。未注入なら解決器をそのまま返す。
 * @returns 判定回数を記録する解決器。
 */
export function countStatusListChecks(
  resolver: StatusListResolver,
  metrics: Metrics | undefined,
): StatusListResolver {
  if (metrics === undefined) {
    return resolver;
  }
  const count = (result: 'success' | 'failure'): void => {
    safeEmit(() => metrics.counter(MetricNames.STATUS_LIST_CHECK_TOTAL, { result }).inc());
  };
  return {
    resolve: async (ref) => {
      try {
        const result = await resolver.resolve(ref);
        count(checkResult(result));
        return result;
      } catch (error) {
        count('failure');
        throw error;
      }
    },
  };
}
