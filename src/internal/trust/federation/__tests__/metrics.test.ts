/**
 * `buildTrustChain` / `verifySubordinate` のメトリクス配線テスト。
 *
 * `trust-chain.test.ts`（既に上限近くの行数）から分離した専用ファイル。3 段チェーン
 * （Leaf → Intermediate → Anchor、`federation-fixtures.ts` の `buildValidTopology`）を 1 回構築し、
 * `vericerts_trust_chain_build_duration_seconds{source=federation}` と
 * `vericerts_federation_statement_fetch_duration_seconds{kind=subordinate-statement, cache=cold}`
 * の両方が実フローから記録されることを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { createInMemoryMetrics, MetricNames } from '../../../observability/metrics.js';
import { buildTrustChain } from '../trust-chain.js';
import { buildValidTopology, makeFetchMock, nowFn } from './federation-fixtures.js';

describe('buildTrustChain のメトリクス配線', () => {
  it('metrics 注入時、trust_chain_build_duration_seconds{source=federation} を記録する', async () => {
    const topo = buildValidTopology();
    const { metrics, snapshot } = createInMemoryMetrics();

    const chain = await buildTrustChain(topo.leafId, topo.anchorId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
      metrics,
    });

    expect(chain.valid).toBe(true);
    const histogram = snapshot().histograms.find(
      (h) => h.name === MetricNames.TRUST_CHAIN_BUILD_DURATION_SECONDS,
    );
    expect(histogram?.labels).toEqual({ source: 'federation' });
    expect(histogram?.count).toBe(1);
  });

  it('同じチェーン構築で subordinate-statement の fetch_duration_seconds も記録する', async () => {
    const topo = buildValidTopology();
    const { metrics, snapshot } = createInMemoryMetrics();

    await buildTrustChain(topo.leafId, topo.anchorId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
      metrics,
    });

    const subordinateSamples = snapshot().histograms.filter(
      (h) =>
        h.name === MetricNames.FEDERATION_STATEMENT_FETCH_DURATION_SECONDS &&
        h.labels.kind === 'subordinate-statement',
    );
    // Intermediate→Leaf・Anchor→Intermediate の 2 件の Subordinate Statement を取得する。
    expect(subordinateSamples.length).toBeGreaterThanOrEqual(1);
    for (const sample of subordinateSamples) {
      expect(sample.labels.cache).toBe('cold');
    }
  });

  it('metrics 未指定でも従来どおり動作する', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.anchorId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });
    expect(chain.valid).toBe(true);
  });
});
