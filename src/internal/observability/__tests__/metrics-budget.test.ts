/**
 * `createMetrics` の単位テスト（ラベルカーディナリティ予算）。
 *
 * 検証内容:
 * 1. 未注入時（`createMetrics(undefined, ...)`）は in-memory 既定へ落ち、例外なく呼べる。
 * 2. `method` の許容外値は注入先へ渡る**前に** `other` へまとめられる。
 * 3. `format` / `result` / `cache` / `source` / `kind` の許容外値は観測ごと拒否され（注入先を
 *    呼ばない）、`metrics.label_rejected` の warn が出る。例外にはしない。
 * 4. `reason` はメトリクス名ごとに 20 種まで通り、21 種目以降は `other` になる。
 * 5. 1 メトリクスあたり組合せ 100 を超えた新しい組合せは全ラベルが `other` へ潰れ、
 *    切り捨て warn はメトリクス名ごとに 1 回だけ出る。
 */

import { describe, expect, it } from 'bun:test';
import type { LogAttributes, Logger } from '../logger.js';
import type { Labels, Metrics } from '../metrics.js';
import { createMetrics } from '../metrics-budget.js';

/** 注入先へ届いた計器取得 1 件。 */
interface RecordedInstrument {
  readonly kind: 'counter' | 'histogram' | 'gauge';
  readonly name: string;
  readonly labels: Labels | undefined;
}

/** 呼び出しを配列に貯めるだけの Metrics（注入先の代役）。計器自体は値を捨てる。 */
function recordingMetrics(): { sink: Metrics; calls: RecordedInstrument[] } {
  const calls: RecordedInstrument[] = [];
  const sink: Metrics = {
    counter(name, labels) {
      calls.push({ kind: 'counter', name, labels });
      return { inc: () => {} };
    },
    histogram(name, labels) {
      calls.push({ kind: 'histogram', name, labels });
      return { observe: () => {} };
    },
    gauge(name, labels) {
      calls.push({ kind: 'gauge', name, labels });
      return { set: () => {}, inc: () => {}, dec: () => {} };
    },
  };
  return { sink, calls };
}

/** 記録したログ 1 件（予算違反の warn を捕まえるためだけに使う）。 */
interface RecordedWarn {
  readonly message: string;
  readonly attrs: LogAttributes | undefined;
}

/** `warn` だけを配列に貯めるロガー。 */
function recordingLogger(): { logger: Logger; warns: RecordedWarn[] } {
  const warns: RecordedWarn[] = [];
  const logger: Logger = {
    debug: () => {},
    info: () => {},
    warn: (message, attrs) => void warns.push({ message, attrs }),
    error: () => {},
    child: () => logger,
  };
  return { logger, warns };
}

/** 記録用の注入先とロガーを繋いだ予算付き Metrics を組み立てる。 */
function setup(): { metrics: Metrics; calls: RecordedInstrument[]; warns: RecordedWarn[] } {
  const { sink, calls } = recordingMetrics();
  const { logger, warns } = recordingLogger();
  return { metrics: createMetrics(sink, logger), calls, warns };
}

describe('createMetrics（未注入時の in-memory 既定）', () => {
  it('3 種の計器がいずれも例外を投げない', () => {
    const { logger } = recordingLogger();
    const metrics = createMetrics(undefined, logger);

    expect(() => {
      metrics.counter('vericerts_did_resolve_total', { method: 'key', result: 'success' }).inc();
      metrics.histogram('vericerts_vc_verify_duration_seconds', { format: 'jwt' }).observe(0.5);
      const gauge = metrics.gauge('vericerts_pending');
      gauge.set(1);
      gauge.inc();
      gauge.dec();
    }).not.toThrow();
  });
});

describe('createMetrics（method ラベル）', () => {
  it('許容値はそのまま注入先へ渡る', () => {
    const { metrics, calls } = setup();

    metrics.counter('m', { method: 'ethr' }).inc();

    expect(calls[0]?.labels).toEqual({ method: 'ethr' });
  });

  it('許容外の値は other へまとめられる（拒否はしない）', () => {
    const { metrics, calls, warns } = setup();

    metrics.counter('m', { method: 'unknownmethod' }).inc();

    expect(calls).toHaveLength(1);
    expect(calls[0]?.labels).toEqual({ method: 'other' });
    // `other` へまとめるのは仕様どおりの正常動作なので警告は出さない。
    expect(warns).toHaveLength(0);
  });

  it('空文字も other へまとめられる', () => {
    const { metrics, calls } = setup();

    metrics.histogram('m', { method: '' }).observe(1);

    expect(calls[0]?.labels).toEqual({ method: 'other' });
  });
});

describe('createMetrics（許可リスト外のラベルの拒否）', () => {
  it.each([
    ['format', 'mdoc'],
    ['result', 'partial'],
    ['cache', 'lukewarm'],
    ['source', 'unknown'],
    ['kind', 'trust-mark'],
  ])('%s の許容外値 %s は観測ごと落とし、注入先を呼ばない', (label, value) => {
    const { metrics, calls, warns } = setup();

    expect(() => metrics.counter('m', { [label]: value }).inc()).not.toThrow();

    expect(calls).toHaveLength(0);
    expect(warns).toHaveLength(1);
    expect(warns[0]?.message).toBe('metrics.label_rejected');
    expect(warns[0]?.attrs).toEqual({ metric: 'm', label, value });
  });

  it('許容値ならそのまま通る', () => {
    const { metrics, calls, warns } = setup();

    metrics.counter('m', { format: 'sd-jwt', result: 'failure', cache: 'hot' }).inc();

    expect(calls[0]?.labels).toEqual({ format: 'sd-jwt', result: 'failure', cache: 'hot' });
    expect(warns).toHaveLength(0);
  });

  it('拒否時は 3 種の計器いずれも no-op を返す（呼んでも落ちない）', () => {
    const { metrics, calls } = setup();

    expect(() => {
      metrics.counter('m', { result: 'bogus' }).inc(3);
      metrics.histogram('m', { result: 'bogus' }).observe(1);
      const gauge = metrics.gauge('m', { result: 'bogus' });
      gauge.set(1);
      gauge.inc();
      gauge.dec();
    }).not.toThrow();
    expect(calls).toHaveLength(0);
  });

  it('予算が列挙していないラベルは素通しする（将来ラベルを潰さない）', () => {
    const { metrics, calls } = setup();

    metrics.counter('m', { flow: 'pre-auth', algorithm: 'AES-256-GCM' }).inc();

    expect(calls[0]?.labels).toEqual({ flow: 'pre-auth', algorithm: 'AES-256-GCM' });
  });
});

describe('createMetrics（reason ラベルの上位 20 種）', () => {
  it('20 種までは素通しし、21 種目以降は other になる', () => {
    const { metrics, calls, warns } = setup();

    for (let i = 0; i < 20; i += 1) {
      metrics.counter('m', { reason: `code${i}` }).inc();
    }
    metrics.counter('m', { reason: 'code20' }).inc();

    expect(calls).toHaveLength(21);
    expect(calls[19]?.labels).toEqual({ reason: 'code19' });
    expect(calls[20]?.labels).toEqual({ reason: 'other' });
    // `other` へまとめるのは仕様どおりの正常動作なので警告は出さない。
    expect(warns).toHaveLength(0);
  });

  it('上限到達後も既知の 20 種は素通しし続ける', () => {
    const { metrics, calls } = setup();
    for (let i = 0; i < 20; i += 1) {
      metrics.counter('m', { reason: `code${i}` }).inc();
    }
    metrics.counter('m', { reason: 'overflow' }).inc();

    metrics.counter('m', { reason: 'code0' }).inc();

    expect(calls.at(-1)?.labels).toEqual({ reason: 'code0' });
  });

  it('既知値の集合はメトリクス名ごとに独立している', () => {
    const { metrics, calls } = setup();
    for (let i = 0; i < 20; i += 1) {
      metrics.counter('a', { reason: `code${i}` }).inc();
    }

    // 別メトリクスの 1 種目なので、`a` が上限に達していても素通しする。
    metrics.counter('b', { reason: 'fresh' }).inc();

    expect(calls.at(-1)).toEqual({ kind: 'counter', name: 'b', labels: { reason: 'fresh' } });
  });
});

describe('createMetrics（組合せ 100 の切り捨て）', () => {
  /** `m` に対し 100 通りの組合せを流し込み、上限到達済みの状態にする。 */
  function fillCombinations(metrics: Metrics, name: string): void {
    for (let i = 0; i < 100; i += 1) {
      metrics.counter(name, { series: `s${i}` }).inc();
    }
  }

  it('100 通りまではそのまま通る', () => {
    const { metrics, calls, warns } = setup();

    fillCombinations(metrics, 'm');

    expect(calls).toHaveLength(100);
    expect(calls[99]?.labels).toEqual({ series: 's99' });
    expect(warns).toHaveLength(0);
  });

  it('101 通り目は全ラベル値が other へ潰れ、warn が 1 回出る', () => {
    const { metrics, calls, warns } = setup();
    fillCombinations(metrics, 'm');

    metrics.counter('m', { series: 's100', method: 'key' }).inc();

    expect(calls).toHaveLength(101);
    expect(calls[100]?.labels).toEqual({ series: 'other', method: 'other' });
    expect(warns).toEqual([{ message: 'metrics.cardinality_truncated', attrs: { metric: 'm' } }]);
  });

  it('102 通り目以降は warn を繰り返さない（同じメトリクスで撒き続けない）', () => {
    const { metrics, warns } = setup();
    fillCombinations(metrics, 'm');

    metrics.counter('m', { series: 's100' }).inc();
    metrics.counter('m', { series: 's101' }).inc();
    metrics.histogram('m', { series: 's102' }).observe(1);

    expect(warns).toHaveLength(1);
  });

  it('上限到達後も記録済みの組合せは元のラベルのまま通る', () => {
    const { metrics, calls } = setup();
    fillCombinations(metrics, 'm');
    metrics.counter('m', { series: 's100' }).inc();

    metrics.counter('m', { series: 's0' }).inc();

    expect(calls.at(-1)?.labels).toEqual({ series: 's0' });
  });

  it('組合せ予算はメトリクス名ごとに独立している', () => {
    const { metrics, calls, warns } = setup();
    fillCombinations(metrics, 'a');

    metrics.counter('b', { series: 'fresh' }).inc();

    expect(calls.at(-1)?.labels).toEqual({ series: 'fresh' });
    expect(warns).toHaveLength(0);
  });
});
