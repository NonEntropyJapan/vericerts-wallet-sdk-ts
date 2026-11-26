/**
 * OpenTelemetry Exporter 実結線アダプタ。
 *
 * `WalletOptions.logger` / `metrics` / `tracer` は SDK が定義するインター
 * フェースであり、Exporter そのもの（`OTLPLogExporter` / `PrometheusExporter` 等）や Provider の
 * 初期化（`NodeSDK` 等）は呼び出し側アプリの責務のままである。本モジュールが提供するのは、
 * 呼び出し側が組み立てた `@opentelemetry/api` / `@opentelemetry/api-logs` の Logger / Meter /
 * Tracer を、これら 3 インターフェースへ変換する薄いアダプタだけである。
 *
 * `@opentelemetry/api` / `@opentelemetry/api-logs` は `peerDependencies`（`optional: true`）であり、
 * 本モジュールを import しない限り SDK のコア（メインバレル）はこれらを一切要求しない。
 * 公開経路をメインバレルから分け
 * `@vericerts/vericerts-wallet-sdk/otel` サブパスに置くのはこのためである（`exports/otel.ts`）。
 *
 * ## Opt-in ゲート（`TelemetryConsent`）
 *
 * 構造化ログ・メトリクス・トレースはいずれも外部送信が既定で無効であり、個別の同意を要する。
 * 本アダプタが橋渡しする Provider は呼び出し側で Exporter が結線されている前提であり、通す
 * こと自体が実質的な外部送信経路になるため、各ファクトリは同意フラグを受け取り、Off の間は
 * 何も転送しない（ログ/トレースは no-op、メトリクスは何も記録しない計器を返す）。
 *
 * 利用者からの同意取得と保存は呼び出し側が担い、記録した同意状態を各アダプタに渡す。
 *
 * @internal
 */

import type {
  Attributes as OtelAttributes,
  AttributeValue as OtelAttributeValue,
  Meter as OtelMeter,
  Tracer as OtelTracer,
} from '@opentelemetry/api';
import { SpanStatusCode } from '@opentelemetry/api';
import type { Logger as OtelLogsApiLogger } from '@opentelemetry/api-logs';
import { SeverityNumber } from '@opentelemetry/api-logs';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { LogAttributes, Logger } from './logger.js';
import type { Counter, Gauge, Histogram, Labels, Metrics } from './metrics.js';
import type { Attributes, AttributeValue, Span, SpanOptions, Tracer } from './tracer.js';

/**
 * テレメトリ外部送信の同意状態。
 *
 * 省略時・各フィールド省略時は仕様どおり `false`（Off）に倒す（fail-closed）。
 */
export interface TelemetryConsent {
  /** 構造化ログの外部送信同意。省略時 `false`。 */
  readonly logs?: boolean;
  /** メトリクスの外部送信同意。省略時 `false`。 */
  readonly metrics?: boolean;
  /** トレースの外部送信同意。省略時 `false`（On でもサンプリングは Provider の Sampler 側の責務）。 */
  readonly traces?: boolean;
}

const LEVEL_TO_SEVERITY: Record<'debug' | 'info' | 'warn' | 'error', SeverityNumber> = {
  debug: SeverityNumber.DEBUG,
  info: SeverityNumber.INFO,
  warn: SeverityNumber.WARN,
  error: SeverityNumber.ERROR,
};

/** 未注入時・Opt-in Off 時の Logger（`logger.ts` の no-op 実装と同形）。 */
const NOOP_LOGGER: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
  child: () => NOOP_LOGGER,
};

/**
 * `@opentelemetry/api-logs` の `Logger` を `Logger` へ変換する。
 *
 * `LogAttributes`（本 SDK の `LogValue`）は `AnyValueMap`（`@opentelemetry/api-logs` の属性型。
 * スカラー / 配列 / ネストしたマップ / `null` を許す）の部分集合であり、値の変換は不要で
 * そのまま渡せる。
 *
 * @param otelLogger 呼び出し側が `logs.getLogger(...)` 等で取得した Provider 由来の Logger。
 * @param consentGranted ログ外部送信の同意。`false`（既定）の間は no-op を返す。
 */
export function createOtelLogger(otelLogger: OtelLogsApiLogger, consentGranted = false): Logger {
  if (!consentGranted) {
    return NOOP_LOGGER;
  }
  return buildOtelLogger(otelLogger, {});
}

function buildOtelLogger(otelLogger: OtelLogsApiLogger, bindings: LogAttributes): Logger {
  const emit =
    (severityNumber: SeverityNumber) =>
    (message: string, attrs?: LogAttributes): void => {
      otelLogger.emit({
        severityNumber,
        body: message,
        attributes: { ...bindings, ...attrs },
      });
    };
  return {
    debug: emit(LEVEL_TO_SEVERITY.debug),
    info: emit(LEVEL_TO_SEVERITY.info),
    warn: emit(LEVEL_TO_SEVERITY.warn),
    error: emit(LEVEL_TO_SEVERITY.error),
    child: (childBindings: LogAttributes) =>
      buildOtelLogger(otelLogger, { ...bindings, ...childBindings }),
  };
}

/**
 * トレース属性の値を OTel の `AttributeValue`（スカラーと同種配列のみ。`null`・ネストしたオブジェクト
 * は不可）へ変換する。
 *
 * 本 SDK の `AttributeValue`（`LogValue` と同形）は `null` / ネストしたオブジェクト /
 * 異種混在配列を許すため、そのままでは OTel 側の型（および「`null`/`undefined` は undefined
 * behavior」という制約）に合わない。プリミティブはそのまま渡し、それ以外（`null`・配列・
 * オブジェクト）は情報を失わないよう JSON エンコードする。異種配列も同種要素専用の OTel 配列型に
 * 当てはまらないため一律 JSON エンコード側に倒す（要素ごとの型判定を避け、規則を 1 つに保つ）。
 */
function toOtelAttributeValue(value: AttributeValue): OtelAttributeValue {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  return JSON.stringify(value);
}

function toOtelAttributes(attrs: Attributes | undefined): OtelAttributes | undefined {
  if (attrs === undefined) {
    return undefined;
  }
  const converted: OtelAttributes = {};
  for (const [key, value] of Object.entries(attrs)) {
    converted[key] = toOtelAttributeValue(value);
  }
  return converted;
}

/** 未注入時・Opt-in Off 時の Span（`tracer.ts` の no-op 実装と同形）。 */
const NOOP_SPAN: Span = {
  setAttribute: () => {},
  addEvent: () => {},
  recordException: () => {},
  setStatus: () => {},
  end: () => {},
};

/**
 * `@opentelemetry/api` の `Tracer` を `Tracer` へ変換する。
 *
 * サンプリング率は Provider に設定した `Sampler` の責務であり、
 * 本アダプタは関与しない。
 *
 * @param otelTracer 呼び出し側が `trace.getTracer(...)` 等で取得した Provider 由来の Tracer。
 * @param consentGranted トレース外部送信の同意。`false`（既定）の間は no-op を返す。
 */
export function createOtelTracer(otelTracer: OtelTracer, consentGranted = false): Tracer {
  if (!consentGranted) {
    return { startSpan: () => NOOP_SPAN };
  }
  return {
    startSpan(name: string, opts?: SpanOptions): Span {
      const span = otelTracer.startSpan(name, {
        attributes: toOtelAttributes(
          opts === undefined ? undefined : ownProperty<Attributes>(opts, 'attributes'),
        ),
      });
      return {
        setAttribute: (key, value) => {
          span.setAttribute(key, toOtelAttributeValue(value));
        },
        addEvent: (eventName, attrs) => {
          span.addEvent(eventName, toOtelAttributes(attrs));
        },
        recordException: (err) => {
          span.recordException(err);
        },
        setStatus: (status, description) => {
          span.setStatus({
            code: status === 'ok' ? SpanStatusCode.OK : SpanStatusCode.ERROR,
            message: description,
          });
        },
        end: () => {
          span.end();
        },
      };
    },
  };
}

/** 未注入時・Opt-in Off 時の Counter/Histogram/Gauge（値を捨てるのみ）。 */
const NOOP_COUNTER: Counter = { inc: () => {} };
const NOOP_HISTOGRAM: Histogram = { observe: () => {} };
const NOOP_GAUGE: Gauge = { set: () => {}, inc: () => {}, dec: () => {} };

/** 未注入時・Opt-in Off 時の Metrics。 */
const NOOP_METRICS: Metrics = {
  counter: () => NOOP_COUNTER,
  histogram: () => NOOP_HISTOGRAM,
  gauge: () => NOOP_GAUGE,
};

/**
 * `@opentelemetry/api` の `Meter` を `Metrics` へ変換する。
 *
 * `buckets`（`Metrics.histogram` 第 3 引数）は OTel の `MetricAdvice.explicitBucketBoundaries`
 * （API 1.7+、`@experimental`）へ渡す。SDK 側の Aggregator 実装が採用するかどうかの助言であり、
 * 必ず反映される保証はない（Prometheus 側でバケットを別途設定する運用も許容する）。
 *
 * `Gauge`（`set`/`inc`/`dec`）は OTel の同期 `Gauge`（`record` のみ）ではなく
 * `UpDownCounter`（加減算）で近似する。直前値との差分を `add` することで `set` を表現する。
 *
 * @param otelMeter 呼び出し側が `metrics.getMeter(...)` 等で取得した Provider 由来の Meter。
 * @param consentGranted メトリクス外部送信の同意。`false`（既定）の間は何も記録しない。
 */
export function createOtelMetrics(otelMeter: OtelMeter, consentGranted = false): Metrics {
  if (!consentGranted) {
    return NOOP_METRICS;
  }
  return {
    counter(name: string, labels?: Labels): Counter {
      const counter = otelMeter.createCounter(name);
      return { inc: (value = 1) => counter.add(value, labels) };
    },
    histogram(name: string, labels?: Labels, buckets?: readonly number[]): Histogram {
      const histogram = otelMeter.createHistogram(name, {
        advice: buckets === undefined ? undefined : { explicitBucketBoundaries: [...buckets] },
      });
      return { observe: (value: number) => histogram.record(value, labels) };
    },
    gauge(name: string, labels?: Labels): Gauge {
      const gauge = otelMeter.createUpDownCounter(name);
      let current = 0;
      return {
        set: (value: number) => {
          gauge.add(value - current, labels);
          current = value;
        },
        inc: (delta = 1) => {
          gauge.add(delta, labels);
          current += delta;
        },
        dec: (delta = 1) => {
          gauge.add(-delta, labels);
          current -= delta;
        },
      };
    },
  };
}
