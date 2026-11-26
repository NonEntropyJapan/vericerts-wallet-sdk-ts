/**
 * `@vericerts/vericerts-wallet-sdk/otel` は OpenTelemetry の Logger、Meter、Tracer を
 * SDK のロガー、メトリクス、トレーサーとして使うためのアダプターを提供する。
 *
 * このサブパスを使う場合は `@opentelemetry/api` と `@opentelemetry/api-logs` をインストールする。
 * SDK のメインエントリーポイントは、これらの optional peer dependencies がなくても利用できる。
 *
 * このサブパスの API は試験提供中（`@experimental`）で、マイナーバージョンの更新で
 * 挙動やシグネチャが変わることがある。呼び出し時に試験提供の警告は表示しない。
 */

import {
  createOtelLogger as createOtelLoggerImpl,
  createOtelMetrics as createOtelMetricsImpl,
  createOtelTracer as createOtelTracerImpl,
} from '../internal/observability/otel-adapter.js';

export type { TelemetryConsent } from '../internal/observability/otel-adapter.js';
export const createOtelLogger = createOtelLoggerImpl;
export const createOtelMetrics = createOtelMetricsImpl;
export const createOtelTracer = createOtelTracerImpl;
