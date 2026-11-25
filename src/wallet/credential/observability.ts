/**
 * `verifyPresentationWith` / `verifySdJwtWith`（`ops.ts`）の replay 検知を
 * `vericerts_nonce_replay_detected_total` に記録する。
 *
 * `ops.ts` は既に長く、計装のためだけの補助関数を増やすと本体（検証ロジック）が読みにくく
 * なるため、`did/observability.ts` と同じ理由でここへ切り出す。
 */

import type { NonceFlow } from '../../internal/auth/nonce/types.js';
import { ErrorCodes, VericertsError } from '../../internal/errors.js';
import { MetricNames, type Metrics } from '../../internal/observability/metrics.js';
import { safeEmit } from '../../internal/observability/safe-emit.js';

/**
 * `NonceContext.flow` を `vericerts_nonce_replay_detected_total` の `context` ラベル
 * へ写す。`oid4vci` と `oid4vp` はそのまま用い、`wua-pop` は `wua` として集計する。
 * その他の flow は誤っていずれかの用途に計上しないよう、一律に `other` とする。
 */
function nonceReplayContext(flow: NonceFlow): string {
  switch (flow) {
    case 'oid4vci':
      return 'oid4vci';
    case 'oid4vp':
      return 'oid4vp';
    case 'wua-pop':
      return 'wua';
    default:
      return 'other';
  }
}

/**
 * Replay 検知（`ErrorCodes.REPLAY_DETECTED`）を `vericerts_nonce_replay_detected_total` へ記録する。
 *
 * Replay 以外のエラー（署名不正・期限切れ等）は本メトリクスの対象外なので記録しない。
 * seen-nonces cache 経路（`nonceStore` / `nonceContext` 指定時）でのみ replay 検知が起こり得る。
 */
export function recordNonceReplayIfDetected(
  metrics: Metrics,
  flow: NonceFlow,
  error: unknown,
): void {
  if (error instanceof VericertsError && error.code === ErrorCodes.REPLAY_DETECTED) {
    safeEmit(() =>
      metrics
        .counter(MetricNames.NONCE_REPLAY_DETECTED_TOTAL, { context: nonceReplayContext(flow) })
        .inc(),
    );
  }
}
