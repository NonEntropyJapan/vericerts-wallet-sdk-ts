/**
 * `createOtelLogger` / `createOtelMetrics` / `createOtelTracer` の回帰テスト。
 *
 * 単なるモック同士の配線確認ではなく、実際の `@opentelemetry/sdk-*`（`BasicTracerProvider` /
 * `MeterProvider` / `LoggerProvider`）に in-memory Exporter を登録した Provider を組み立て、
 * アダプタ経由で記録した値が実際の Exporter に届くことを検証する。
 *
 * Opt-in の処理が未実装のため、本アダプタは `consentGranted` 引数を
 * プレースホルダとして受け取るのみ（判定ロジックの実体は持たない）。ここでは
 * 1. 既定（省略）で no-op になること（fail-closed）
 * 2. `true` を渡したときのみ実際に Provider まで届くこと
 * の両方を確認する。
 */

import { describe, expect, test } from 'bun:test';
import { trace } from '@opentelemetry/api';
import { logs, SeverityNumber } from '@opentelemetry/api-logs';
import {
  InMemoryLogRecordExporter,
  LoggerProvider,
  SimpleLogRecordProcessor,
} from '@opentelemetry/sdk-logs';
import {
  AggregationTemporality,
  InMemoryMetricExporter,
  MeterProvider,
  PeriodicExportingMetricReader,
} from '@opentelemetry/sdk-metrics';
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from '@opentelemetry/sdk-trace-base';
import { createOtelLogger, createOtelMetrics, createOtelTracer } from '../otel-adapter.js';

describe('createOtelTracer', () => {
  function setup() {
    const exporter = new InMemorySpanExporter();
    const provider = new BasicTracerProvider({
      spanProcessors: [new SimpleSpanProcessor(exporter)],
    });
    const tracer = provider.getTracer('otel-adapter-test');
    return { exporter, provider, tracer };
  }

  test('Opt-in Off（既定）では Provider に何も届かない', async () => {
    const { exporter, provider, tracer } = setup();
    const adapted = createOtelTracer(tracer);
    const span = adapted.startSpan('vc.verify', { attributes: { 'vc.format': 'jwt' } });
    span.setAttribute('vc.result', 'success');
    span.setStatus('ok');
    span.end();
    await provider.forceFlush();
    expect(exporter.getFinishedSpans()).toHaveLength(0);
  });

  test('Opt-in On では実際の Span として Provider まで届く', async () => {
    const { exporter, provider, tracer } = setup();
    const adapted = createOtelTracer(tracer, true);

    const span = adapted.startSpan('vc.verify', { attributes: { 'vc.format': 'jwt' } });
    span.setAttribute('vc.result', 'success');
    span.addEvent('status_checked', { 'vc.status_check': true });
    span.setStatus('ok');
    span.end();
    await provider.forceFlush();

    const finished = exporter.getFinishedSpans();
    expect(finished).toHaveLength(1);
    expect(finished[0]?.name).toBe('vc.verify');
    expect(finished[0]?.attributes['vc.format']).toBe('jwt');
    expect(finished[0]?.attributes['vc.result']).toBe('success');
    expect(finished[0]?.events[0]?.name).toBe('status_checked');
  });

  test('null・ネストした属性値は JSON エンコードされて渡る（OTel の AttributeValue は非対応のため）', async () => {
    const { exporter, provider, tracer } = setup();
    const adapted = createOtelTracer(tracer, true);

    const span = adapted.startSpan('did.resolve');
    span.setAttribute('did.result', null);
    span.setAttribute('did.detail', { nested: true });
    span.end();
    await provider.forceFlush();

    const finished = exporter.getFinishedSpans();
    expect(finished[0]?.attributes['did.result']).toBe('null');
    expect(finished[0]?.attributes['did.detail']).toBe('{"nested":true}');
  });

  test('例外は recordException 経由で Provider に届く', async () => {
    const { exporter, provider, tracer } = setup();
    const adapted = createOtelTracer(tracer, true);

    const span = adapted.startSpan('vc.verify');
    span.recordException(new Error('boom'));
    span.setStatus('error', 'VC_VERIFICATION_FAILED');
    span.end();
    await provider.forceFlush();

    const finished = exporter.getFinishedSpans();
    expect(finished[0]?.events[0]?.name).toBe('exception');
    expect(finished[0]?.status.message).toBe('VC_VERIFICATION_FAILED');
  });
});

describe('createOtelMetrics', () => {
  function setup() {
    const exporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE);
    const reader = new PeriodicExportingMetricReader({
      exporter,
      exportIntervalMillis: 100_000, // テストでは forceFlush で明示的に読み出すため長め。
    });
    const provider = new MeterProvider({ readers: [reader] });
    const meter = provider.getMeter('otel-adapter-test');
    return { exporter, provider, meter };
  }

  test('Opt-in Off（既定）では何も記録されない', async () => {
    const { exporter, provider, meter } = setup();
    const metrics = createOtelMetrics(meter);
    metrics.counter('vericerts_did_resolve_total', { method: 'key', result: 'success' }).inc();
    await provider.forceFlush();
    expect(exporter.getMetrics()).toHaveLength(0);
  });

  test('counter / histogram / gauge が実際の Meter へ記録される', async () => {
    const { exporter, provider, meter } = setup();
    const metrics = createOtelMetrics(meter, true);

    metrics.counter('vericerts_did_resolve_total', { method: 'key', result: 'success' }).inc();
    metrics
      .histogram(
        'vericerts_did_resolve_duration_seconds',
        { method: 'key', cache: 'hot' },
        [0.01, 0.1, 1],
      )
      .observe(0.05);
    const gauge = metrics.gauge('vericerts_active_sessions');
    gauge.set(3);
    gauge.inc();
    gauge.dec(2);

    await provider.forceFlush();
    const exported = exporter.getMetrics();
    const names = exported.flatMap((batch) =>
      batch.scopeMetrics.flatMap((scope) => scope.metrics.map((metric) => metric.descriptor.name)),
    );
    expect(names).toContain('vericerts_did_resolve_total');
    expect(names).toContain('vericerts_did_resolve_duration_seconds');
    expect(names).toContain('vericerts_active_sessions');
  });
});

describe('createOtelLogger', () => {
  function setup() {
    const exporter = new InMemoryLogRecordExporter();
    const provider = new LoggerProvider({
      processors: [new SimpleLogRecordProcessor({ exporter })],
    });
    const logger = provider.getLogger('otel-adapter-test');
    return { exporter, provider, logger };
  }

  test('Opt-in Off（既定）では何も出力されない', async () => {
    const { exporter, provider, logger } = setup();
    const adapted = createOtelLogger(logger);
    adapted.info('did resolved', { did_method: 'key' });
    await provider.forceFlush();
    expect(exporter.getFinishedLogRecords()).toHaveLength(0);
  });

  test('レベルごとに正しい SeverityNumber で Provider へ届く', async () => {
    const { exporter, provider, logger } = setup();
    const adapted = createOtelLogger(logger, true);

    adapted.debug('debug msg');
    adapted.info('info msg');
    adapted.warn('warn msg');
    adapted.error('error msg', { error_code: '2003' });
    await provider.forceFlush();

    const records = exporter.getFinishedLogRecords();
    expect(records).toHaveLength(4);
    expect(records.map((r) => r.severityNumber)).toEqual([
      SeverityNumber.DEBUG,
      SeverityNumber.INFO,
      SeverityNumber.WARN,
      SeverityNumber.ERROR,
    ]);
    expect(records[3]?.attributes.error_code).toBe('2003');
  });

  test('child() の束縛属性が以降の出力すべてに引き継がれる', async () => {
    const { exporter, provider, logger } = setup();
    const adapted = createOtelLogger(logger, true);
    const child = adapted.child({ component: 'sdk.did' });

    child.info('did resolved', { did_method: 'key' });
    await provider.forceFlush();

    const [record] = exporter.getFinishedLogRecords();
    expect(record?.attributes.component).toBe('sdk.did');
    expect(record?.attributes.did_method).toBe('key');
  });
});

test('trace / logs API の getTracer / getLogger を経由しても同じ挙動になる（呼び出し側の実利用形態）', async () => {
  // グローバル API 経由で取得した Tracer / Logger でも同じ挙動になることを確かめる。
  const spanExporter = new InMemorySpanExporter();
  const tracerProvider = new BasicTracerProvider({
    spanProcessors: [new SimpleSpanProcessor(spanExporter)],
  });
  trace.setGlobalTracerProvider(tracerProvider);

  const logExporter = new InMemoryLogRecordExporter();
  const loggerProvider = new LoggerProvider({
    processors: [new SimpleLogRecordProcessor({ exporter: logExporter })],
  });
  logs.setGlobalLoggerProvider(loggerProvider);

  const tracer = createOtelTracer(trace.getTracer('vericerts-wallet'), true);
  const logger = createOtelLogger(logs.getLogger('vericerts-wallet'), true);

  const span = tracer.startSpan('oid4vci.issuance');
  span.end();
  logger.info('issued');

  await tracerProvider.forceFlush();
  await loggerProvider.forceFlush();

  expect(spanExporter.getFinishedSpans()).toHaveLength(1);
  expect(logExporter.getFinishedLogRecords()).toHaveLength(1);
});
