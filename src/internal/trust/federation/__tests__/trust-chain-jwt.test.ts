/**
 * `buildTrustChain` が各ノードに生 compact JWT（`TrustChainNode.jwt`）を配線することの回帰テスト。
 * 実鍵 P-256 で署名し、`fetch` はモックを使う。
 *
 * `FederationEntityCache.trustChain` は「Leaf → Trust Anchor 順の JWT 列」であり、1 ノードでも
 * `jwt` が欠ければ組み立てられない（`toFederationEntityCache` は 5010 で不成立にする）。leaf EC /
 * subordinate / trust anchor EC の 3 経路はそれぞれ別の代入点なので、すべてを個別に押さえる。
 *
 * 本ファイルが `trust-chain.test.ts` と分かれているのは Linterly の 1 ファイル 300 行上限のため
 * （`statement-cache/` の分割と同じ理由）。チェーン構築そのものの検証は `trust-chain.test.ts`。
 */

import { describe, expect, it } from 'bun:test';
import { buildTrustChain } from '../trust-chain.js';
import { buildValidTopology, makeFetchMock, nowFn } from './federation-fixtures.js';

describe('buildTrustChain - TrustChainNode.jwt の配線', () => {
  it('3 段チェーンの全ノードが検証対象の生 JWT を保持する', async () => {
    const topo = buildValidTopology();

    const chain = await buildTrustChain(topo.leafId, topo.anchorId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });

    // Leaf EC → Sub(Int→Leaf) → Sub(Anchor→Int) → Anchor EC の順。
    expect(chain.nodes.map((node) => node.jwt)).toEqual([
      topo.responses.get(`${topo.leafId}/.well-known/openid-federation`),
      topo.responses.get(`${topo.intermediateId}/fetch?sub=${encodeURIComponent(topo.leafId)}`),
      topo.responses.get(`${topo.anchorId}/fetch?sub=${encodeURIComponent(topo.intermediateId)}`),
      topo.responses.get(`${topo.anchorId}/.well-known/openid-federation`),
    ]);
  });

  it('Leaf 自身が Trust Anchor の退化ケース（1 段）でも生 JWT を保持する', async () => {
    const topo = buildValidTopology();

    const chain = await buildTrustChain(topo.leafId, topo.leafId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });

    expect(chain.nodes).toHaveLength(1);
    expect(chain.nodes[0]?.jwt).toBe(
      topo.responses.get(`${topo.leafId}/.well-known/openid-federation`) as string,
    );
  });
});
