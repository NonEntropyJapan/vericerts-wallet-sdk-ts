/**
 * `createInMemoryMetrics` の単位テスト。
 *
 * 検証内容:
 * 1. 同じ `name` + ラベルの繰り返し呼び出しが 1 系列へ積み上がる（呼び出しごとに新しい計器を
 *    作っていれば値が分裂して検知できる）。
 * 2. ラベルが違えば別系列に分かれ、宣言順の違いだけでは分かれない。
 * 3. カウンタ・ヒストグラム・ゲージそれぞれの既定引数（`inc()` / `dec()` の 1）。
 *
 * ラベルカーディナリティ予算は `metrics-budget.test.ts`。
 */

import { describe, expect, it } from 'bun:test';
import type { Labels, MetricSample } from '../metrics.js';
import { createInMemoryMetrics, MetricNames } from '../metrics.js';

/** 指定した `name` + ラベルの系列 1 件を探す（無ければ `undefined`）。 */
function findSample<T extends { name: string; labels: Labels }>(
  samples: readonly T[],
  name: string,
  labels: Labels,
): T | undefined {
  return samples.find((sample) => sample.name === name && Bun.deepEquals(sample.labels, labels));
}

describe('createInMemoryMetrics（既定の in-memory 実装）', () => {
  it('同じ name + ラベルのカウンタは 1 系列へ積み上がる', () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    const labels = { method: 'key', result: 'success' };

    metrics.counter(MetricNames.DID_RESOLVE_TOTAL, labels).inc();
    metrics.counter(MetricNames.DID_RESOLVE_TOTAL, labels).inc(2);

    expect(snapshot().counters).toHaveLength(1);
    expect(findSample(snapshot().counters, MetricNames.DID_RESOLVE_TOTAL, labels)?.value).toBe(3);
  });

  it('ラベルが違えば別系列になる', () => {
    const { metrics, snapshot } = createInMemoryMetrics();

    metrics.counter('vericerts_did_resolve_total', { method: 'key' }).inc();
    metrics.counter('vericerts_did_resolve_total', { method: 'web' }).inc();

    expect(snapshot().counters.map((sample: MetricSample) => sample.value)).toEqual([1, 1]);
  });

  it('ラベルの宣言順が違うだけでは系列が分かれない', () => {
    const { metrics, snapshot } = createInMemoryMetrics();

    metrics.counter('m', { a: '1', b: '2' }).inc();
    metrics.counter('m', { b: '2', a: '1' }).inc();

    expect(snapshot().counters).toHaveLength(1);
    expect(snapshot().counters[0]?.value).toBe(2);
  });

  it('ヒストグラムは件数と合計を積む（バケットは保持しない）', () => {
    const { metrics, snapshot } = createInMemoryMetrics();

    const histogram = metrics.histogram(
      'vericerts_vc_verify_duration_seconds',
      { format: 'jwt' },
      [0.1, 1],
    );
    histogram.observe(0.25);
    metrics.histogram('vericerts_vc_verify_duration_seconds', { format: 'jwt' }).observe(0.75);

    expect(snapshot().histograms).toHaveLength(1);
    expect(snapshot().histograms[0]?.count).toBe(2);
    expect(snapshot().histograms[0]?.sum).toBeCloseTo(1, 10);
  });

  it('ゲージは set / inc / dec で現在値を持つ（既定の増減幅は 1）', () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    const gauge = metrics.gauge('vericerts_pending', { kind: 'x' });

    gauge.set(5);
    gauge.inc();
    gauge.inc(3);
    gauge.dec();

    expect(snapshot().gauges[0]?.value).toBe(8);
  });

  it('カウンタの既定増分は 1', () => {
    const { metrics, snapshot } = createInMemoryMetrics();

    metrics.counter('m').inc();

    expect(snapshot().counters[0]).toEqual({ name: 'm', labels: {}, value: 1 });
  });

  it('スナップショットは呼び出し側のラベル参照を持ち越さない', () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    const labels: Labels = { method: 'key' };

    metrics.counter('m', labels).inc();
    labels.method = 'web';

    expect(snapshot().counters[0]?.labels).toEqual({ method: 'key' });
  });

  it('カウンタ・ヒストグラム・ゲージは同名でも互いに混ざらない', () => {
    const { metrics, snapshot } = createInMemoryMetrics();

    metrics.counter('m').inc(2);
    metrics.histogram('m').observe(7);
    metrics.gauge('m').set(9);

    const state = snapshot();
    expect(state.counters[0]?.value).toBe(2);
    expect(state.histograms[0]).toMatchObject({ count: 1, sum: 7 });
    expect(state.gauges[0]?.value).toBe(9);
  });
});

describe('MetricNames（命名規約）', () => {
  it('配線済みメトリクス名がすべて vericerts_ 接頭辞 + 単位サフィックスを持つ', () => {
    expect(Object.values(MetricNames)).toEqual([
      'vericerts_did_resolve_total',
      'vericerts_did_resolve_duration_seconds',
      'vericerts_vc_verify_total',
      'vericerts_vc_verify_duration_seconds',
      'vericerts_status_list_fetch_duration_seconds',
      'vericerts_status_list_check_total',
      'vericerts_storage_encrypt_duration_seconds',
      'vericerts_nonce_replay_detected_total',
      'vericerts_bundler_userop_total',
      'vericerts_federation_statement_fetch_duration_seconds',
      'vericerts_trust_chain_build_duration_seconds',
      'vericerts_pid_issuance_total',
      'vericerts_oid4vp_response_duration_seconds',
      'vericerts_wua_refresh_total',
      'vericerts_oid4vci_token_duration_seconds',
    ]);
  });

  it('個々の名前が命名規約（小文字スネークケース・vericerts_ 接頭辞・単位サフィックス）に従う', () => {
    for (const name of Object.values(MetricNames)) {
      expect(name).toMatch(/^vericerts_[a-z0-9_]+_(total|seconds|bytes)$/);
    }
  });
});
