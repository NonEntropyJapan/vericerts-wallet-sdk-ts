/**
 * buildTrustChain / verifyTrustAnchor / jwksEqual のユニット・統合テスト。
 * 実鍵 P-256 で署名し、`fetch` はモックを使う。
 *
 * 検証内容:
 * - 正常系（統合）: Leaf → Intermediate → Anchor の 3 段チェーン構築成功（信頼アンカー検証）。
 * - Leaf 自身が Trust Anchor の 1 段チェーン。
 * - Trust Anchor に到達不能（authority_hints が別 anchor）→ TRUST_CHAIN_INVALID（5010）。
 * - Subordinate Statement の鍵不一致（child jwks 偽装）→ TRUST_CHAIN_INVALID。
 * - Subordinate Statement を上位以外の鍵で署名 → TRUST_CHAIN_INVALID。
 * - federation_fetch_endpoint 欠落 → TRUST_CHAIN_INVALID。
 * - authority_hints 循環 → TRUST_CHAIN_INVALID。
 * - verifyTrustAnchor: 成立で true、不成立で false、取得失敗は送出。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import type { JsonWebKeySet } from '../federation-types.js';
import { verifyTrustAnchor } from '../trust-anchor-verify.js';
import { buildTrustChain, jwksEqual } from '../trust-chain.js';
import {
  ANCHOR_KEY,
  buildValidTopology,
  INTERMEDIATE_KEY,
  LEAF_KEY,
  makeFetchMock,
  nowFn,
  signStatement,
  toJwk,
  validPeriod,
  WRONG_KEY,
} from './federation-fixtures.js';

/** reject が指定コードの VericertsError であることを検証する。 */
async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

describe('buildTrustChain - 正常系（統合: 信頼アンカー検証）', () => {
  it('Leaf → Intermediate → Anchor の 3 段チェーンを構築する', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.anchorId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });
    expect(chain.valid).toBe(true);
    expect(chain.leaf).toBe(topo.leafId);
    expect(chain.trustAnchor).toBe(topo.anchorId);
    // Leaf EC + Sub(Int→Leaf) + Sub(Anchor→Int) + Anchor EC = 4 ノード。
    expect(chain.length).toBe(chain.nodes.length);
    expect(chain.nodes[0]?.kind).toBe('entity-configuration');
    expect(chain.nodes[0]?.sub).toBe(topo.leafId);
    expect(chain.nodes[chain.nodes.length - 1]?.kind).toBe('entity-configuration');
    expect(chain.nodes[chain.nodes.length - 1]?.sub).toBe(topo.anchorId);
  });

  it('Leaf 自身が Trust Anchor の場合は 1 段チェーン', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.leafId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });
    expect(chain.valid).toBe(true);
    expect(chain.length).toBe(1);
    expect(chain.nodes[0]?.sub).toBe(topo.leafId);
  });
});

describe('buildTrustChain - 不成立（5010）', () => {
  it('Trust Anchor に到達不能（別 anchor 指定）は TRUST_CHAIN_INVALID', async () => {
    const topo = buildValidTopology();
    await expectRejectCode(
      buildTrustChain(topo.leafId, 'https://unknown-anchor.example.eu', {
        fetchFn: makeFetchMock(topo.responses),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('Subordinate Statement が保証する child 鍵の不一致は TRUST_CHAIN_INVALID', async () => {
    const topo = buildValidTopology();
    // Intermediate → Leaf の Subordinate を、Leaf の実鍵と異なる jwks を保証する形に差し替える。
    const intFetch = `${topo.intermediateId}/fetch`;
    const tampered = signStatement(INTERMEDIATE_KEY, {
      iss: topo.intermediateId,
      sub: topo.leafId,
      ...validPeriod(),
      jwks: { keys: [toJwk(WRONG_KEY, 'wrong-1')] },
    });
    topo.responses.set(`${intFetch}?sub=${encodeURIComponent(topo.leafId)}`, tampered);
    await expectRejectCode(
      buildTrustChain(topo.leafId, topo.anchorId, {
        fetchFn: makeFetchMock(topo.responses),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('Subordinate Statement を上位以外の鍵で署名すると TRUST_CHAIN_INVALID', async () => {
    const topo = buildValidTopology();
    const intFetch = `${topo.intermediateId}/fetch`;
    // Intermediate ではなく WRONG_KEY で署名（上位鍵で検証不成立）。
    const badlySigned = signStatement(WRONG_KEY, {
      iss: topo.intermediateId,
      sub: topo.leafId,
      ...validPeriod(),
      jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
    });
    topo.responses.set(`${intFetch}?sub=${encodeURIComponent(topo.leafId)}`, badlySigned);
    await expectRejectCode(
      buildTrustChain(topo.leafId, topo.anchorId, {
        fetchFn: makeFetchMock(topo.responses),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('上位に federation_fetch_endpoint が無いと TRUST_CHAIN_INVALID', async () => {
    // Intermediate の EC から fetch endpoint を除去した 2 段トポロジ。
    const leafId = 'https://leaf.example.eu';
    const anchorId = 'https://anchor.example.eu';
    const leafJwks = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };
    const anchorJwks = { keys: [toJwk(ANCHOR_KEY, 'anchor-1')] };
    const leafEc = signStatement(LEAF_KEY, {
      iss: leafId,
      sub: leafId,
      ...validPeriod(),
      jwks: leafJwks,
      authority_hints: [anchorId],
    });
    // Anchor EC に federation_fetch_endpoint を含めない。
    const anchorEc = signStatement(ANCHOR_KEY, {
      iss: anchorId,
      sub: anchorId,
      ...validPeriod(),
      jwks: anchorJwks,
    });
    const responses = new Map<string, string>();
    responses.set(`${leafId}/.well-known/openid-federation`, leafEc);
    responses.set(`${anchorId}/.well-known/openid-federation`, anchorEc);
    await expectRejectCode(
      buildTrustChain(leafId, anchorId, { fetchFn: makeFetchMock(responses), now: nowFn }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('authority_hints が空（上位なし）だと TRUST_CHAIN_INVALID', async () => {
    const leafId = 'https://leaf.example.eu';
    const anchorId = 'https://anchor.example.eu';
    const leafEc = signStatement(LEAF_KEY, {
      iss: leafId,
      sub: leafId,
      ...validPeriod(),
      jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
    });
    const responses = new Map<string, string>();
    responses.set(`${leafId}/.well-known/openid-federation`, leafEc);
    await expectRejectCode(
      buildTrustChain(leafId, anchorId, { fetchFn: makeFetchMock(responses), now: nowFn }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('authority_hints の循環参照は TRUST_CHAIN_INVALID', async () => {
    // Leaf → A → Leaf の循環（Trust Anchor には到達しない）。
    const leafId = 'https://leaf.example.eu';
    const aId = 'https://a.example.eu';
    const anchorId = 'https://anchor.example.eu';
    const leafJwks = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };
    const aJwks = { keys: [toJwk(INTERMEDIATE_KEY, 'a-1')] };
    const aFetch = `${aId}/fetch`;
    const leafEc = signStatement(LEAF_KEY, {
      iss: leafId,
      sub: leafId,
      ...validPeriod(),
      jwks: leafJwks,
      authority_hints: [aId],
    });
    const aEc = signStatement(INTERMEDIATE_KEY, {
      iss: aId,
      sub: aId,
      ...validPeriod(),
      jwks: aJwks,
      authority_hints: [leafId],
      metadata: { federation_entity: { federation_fetch_endpoint: aFetch } },
    });
    const aAboutLeaf = signStatement(INTERMEDIATE_KEY, {
      iss: aId,
      sub: leafId,
      ...validPeriod(),
      jwks: leafJwks,
    });
    const responses = new Map<string, string>();
    responses.set(`${leafId}/.well-known/openid-federation`, leafEc);
    responses.set(`${aId}/.well-known/openid-federation`, aEc);
    responses.set(`${aFetch}?sub=${encodeURIComponent(leafId)}`, aAboutLeaf);
    await expectRejectCode(
      buildTrustChain(leafId, anchorId, { fetchFn: makeFetchMock(responses), now: nowFn }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });
});

describe('buildTrustChain - 最大段数', () => {
  /**
   * n 個のエンティティが一直線に連なるトポロジを構築する（全て LEAF_KEY で署名 = jwks 共通）。
   * e0（Leaf）→ e1 → ... → e{n-1}（Anchor）。各上位が下位の Subordinate Statement を発行する。
   */
  function buildLinearTopology(n: number): {
    leaf: string;
    anchor: string;
    responses: Map<string, string>;
  } {
    const ids = Array.from({ length: n }, (_, i) => `https://e${i}.example.eu`);
    const jwks = { keys: [toJwk(LEAF_KEY, 'k')] };
    const responses = new Map<string, string>();
    for (let i = 0; i < n; i++) {
      const isAnchor = i === n - 1;
      const payload: Record<string, unknown> = {
        iss: ids[i],
        sub: ids[i],
        ...validPeriod(),
        jwks,
      };
      if (!isAnchor) {
        payload.authority_hints = [ids[i + 1]];
      }
      // Anchor 以外（下位を持つ上位）は fetch endpoint を持つ。
      const fetchEndpoint = `${ids[i]}/fetch`;
      payload.metadata = { federation_entity: { federation_fetch_endpoint: fetchEndpoint } };
      responses.set(`${ids[i]}/.well-known/openid-federation`, signStatement(LEAF_KEY, payload));
    }
    // 各上位 e{i+1} が下位 e{i} についての Subordinate Statement を発行する。
    for (let i = 0; i < n - 1; i++) {
      const parent = ids[i + 1];
      const child = ids[i];
      const sub = signStatement(LEAF_KEY, {
        iss: parent,
        sub: child,
        ...validPeriod(),
        jwks,
      });
      responses.set(`${parent}/fetch?sub=${encodeURIComponent(child as string)}`, sub);
    }
    return { leaf: ids[0] as string, anchor: ids[n - 1] as string, responses };
  }

  it('5 段（MAX_TRUST_CHAIN_LENGTH）までは構築できる', async () => {
    const topo = buildLinearTopology(5);
    const chain = await buildTrustChain(topo.leaf, topo.anchor, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });
    expect(chain.valid).toBe(true);
  });

  it('6 段（MAX 超過）は TRUST_CHAIN_INVALID', async () => {
    const topo = buildLinearTopology(6);
    await expectRejectCode(
      buildTrustChain(topo.leaf, topo.anchor, {
        fetchFn: makeFetchMock(topo.responses),
        now: nowFn,
      }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });
});

describe('verifyTrustAnchor', () => {
  it('チェーン成立で true', async () => {
    const topo = buildValidTopology();
    const ok = await verifyTrustAnchor(topo.leafId, topo.anchorId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });
    expect(ok).toBe(true);
  });

  it('チェーン不成立で false（例外を投げない）', async () => {
    const topo = buildValidTopology();
    const ok = await verifyTrustAnchor(topo.leafId, 'https://unknown-anchor.example.eu', {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });
    expect(ok).toBe(false);
  });

  it('Entity Configuration 取得失敗（5011）は送出する', async () => {
    const fetchFn = (async (_input: string | URL) =>
      new Response('nf', { status: 404 })) as typeof fetch;
    await expectRejectCode(
      verifyTrustAnchor('https://leaf.example.eu', 'https://anchor.example.eu', {
        fetchFn,
        now: nowFn,
      }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });
});

describe('jwksEqual', () => {
  it('同一鍵集合は順序・キー順に依らず一致する', () => {
    const a: JsonWebKeySet = { keys: [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB' }] };
    const b: JsonWebKeySet = { keys: [{ crv: 'P-256', y: 'BB', x: 'AA', kty: 'EC' }] };
    expect(jwksEqual(a, b)).toBe(true);
  });

  it('異なる鍵集合は不一致', () => {
    const a: JsonWebKeySet = { keys: [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB' }] };
    const b: JsonWebKeySet = { keys: [{ kty: 'EC', crv: 'P-256', x: 'CC', y: 'DD' }] };
    expect(jwksEqual(a, b)).toBe(false);
  });
});
