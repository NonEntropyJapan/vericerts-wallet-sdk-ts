/**
 * DID 解決時にログ・メトリクス・トレースを記録する。各出力先は個別に差し替えられる。
 *
 * ログ属性 `did_method`・Span 属性 `did.method`・メトリクスラベル `method` は下の `didMethod`
 * 1 箇所から作る。別々に切り出すと、同じ解決についてログ・Span・メトリクスで違うメソッド名が
 * 付く余地が残るためである。
 *
 * 解決時の例外はそのまま再送出する。生の DID や URL は出力に含めない。
 */

import type { DIDDocument } from '../../internal/identity/did.js';
import type { Resolver } from '../../internal/identity/resolver.js';
import {
  errorLogAttributes,
  type LogAttributes,
  type Logger,
} from '../../internal/observability/logger.js';
import type { Metrics } from '../../internal/observability/metrics.js';
import { safeEmit } from '../../internal/observability/safe-emit.js';
import { type Tracer, traceSpan } from '../../internal/observability/tracer.js';
import { recordDidResolveMetrics } from './observability.js';

/** Span 名（`<component>.<operation>`）兼ログメッセージ。 */
const DID_RESOLVE = 'did.resolve';

/** 成否を記録する Span 属性。 */
const RESULT_ATTRIBUTE = 'did.result';

/**
 * DID 文字列から、ログの `did_method` と Span の `did.method` に使うメソッド名を取り出す。
 *
 * `did:<method>:<id>` の形でないものはメソッドを名乗れないため、推測せず `undefined` を返す
 * （形式不正の入力から作った偽のメソッド名を集計軸に混ぜない）。
 */
function didMethod(did: string): string | undefined {
  const segments = did.split(':');
  const method = segments[1] ?? '';
  return segments[0] === 'did' && segments.length >= 3 && method !== '' ? method : undefined;
}

/**
 * DID 文字列を DID Document に解決し、成否とレイテンシをログ・メトリクス・Span へ記録する。
 *
 * Resolver はこの計装にキャッシュのヒットを通知しないため、Span から `did.cache_hit` を省き、
 * メトリクスの `cache` ラベルには固定値 `cold` を使う。
 *
 * @param resolver DID メソッドの登録先。
 * @param did 解決対象の DID 文字列。
 * @param logger `component: 'sdk.did'` を束縛済みのロガー。
 * @param metrics ラベルのカーディナリティ制限を適用済みのメトリクス。
 * @param tracer 出力先（未注入時は no-op）。
 */
export async function resolveDidWith(
  resolver: Resolver,
  did: string,
  logger: Logger,
  metrics: Metrics,
  tracer: Tracer,
): Promise<DIDDocument> {
  const method = didMethod(did);
  const attrs: LogAttributes = {
    operation: DID_RESOLVE,
    ...(method === undefined ? {} : { did_method: method }),
  };
  return traceSpan(tracer, DID_RESOLVE, RESULT_ATTRIBUTE, async (span) => {
    if (method !== undefined) {
      span.setAttribute('did.method', method);
    }
    const startedAt = Date.now();
    let document: DIDDocument;
    try {
      document = await resolver.resolve(did);
    } catch (error) {
      const durationMs = Date.now() - startedAt;
      // テレメトリの失敗で元のエラー（VericertsError のコード）を置換しない。
      safeEmit(() => {
        logger.error(DID_RESOLVE, {
          ...attrs,
          duration_ms: durationMs,
          ...errorLogAttributes(error),
        });
      });
      safeEmit(() => recordDidResolveMetrics(metrics, method, 'failure', durationMs));
      throw error;
    }
    // 実測は 1 回だけ取り、ログ（ミリ秒）とメトリクス（秒）で同じ値を使う。
    const durationMs = Date.now() - startedAt;
    // 解決は成功済み。テレメトリの失敗で成功結果を reject に変えない。
    safeEmit(() => {
      logger.info(DID_RESOLVE, { ...attrs, duration_ms: durationMs });
    });
    safeEmit(() => recordDidResolveMetrics(metrics, method, 'success', durationMs));
    return document;
  });
}
