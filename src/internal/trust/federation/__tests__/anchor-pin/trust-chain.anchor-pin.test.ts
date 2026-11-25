/**
 * OIDF Trust Anchor 鍵のピン留めの回帰テスト。
 *
 * Anchor の Entity Configuration は自己署名なので、ピン留め無しでは TLS だけが根拠になる。
 * ピン留め鍵（`options.trustAnchorJwks`）を指定したチェーンは、Anchor EC がその鍵で署名されて
 * いなければ TRUST_CHAIN_INVALID になる。未指定の挙動（自己署名のみ・`anchorPinned: false`）は不変。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { verifyTrustAnchor } from '../../trust-anchor-verify.js';
import { buildTrustChain } from '../../trust-chain.js';
import {
  ANCHOR_KEY,
  buildValidTopology,
  makeFetchMock,
  nowFn,
  signStatement,
  toJwk,
  validPeriod,
  WRONG_KEY,
} from '../federation-fixtures.js';

const pinnedJwks = { keys: [toJwk(ANCHOR_KEY, 'anchor-1')] };

async function rejectionCode(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (error) {
    return error instanceof VericertsError ? error.code : 'other';
  }
  return undefined;
}

/**
 * Anchor EC / Anchor→Intermediate の Subordinate Statement を攻撃者鍵で作り直したトポロジ
 * （TLS 終端を握った攻撃者が返す応答）。ピン留め無しでは正規と区別できず `valid: true` になる。
 */
function forgedAnchorTopology() {
  const topo = buildValidTopology();
  const anchorFetch = `${topo.anchorId}/fetch`;
  const forgedJwks = { keys: [toJwk(WRONG_KEY, 'anchor-1')] };
  topo.responses.set(
    `${topo.anchorId}/.well-known/openid-federation`,
    signStatement(
      WRONG_KEY,
      {
        iss: topo.anchorId,
        sub: topo.anchorId,
        ...validPeriod(),
        jwks: forgedJwks,
        metadata: { federation_entity: { federation_fetch_endpoint: anchorFetch } },
      },
      { kid: 'anchor-1' },
    ),
  );
  const intermediateJwks = { keys: [toJwk(new Uint8Array(32).fill(13), 'int-1')] };
  topo.responses.set(
    `${anchorFetch}?sub=${encodeURIComponent(topo.intermediateId)}`,
    signStatement(WRONG_KEY, {
      iss: topo.anchorId,
      sub: topo.intermediateId,
      ...validPeriod(),
      jwks: intermediateJwks,
    }),
  );
  return topo;
}

const depsOf = (responses: Map<string, string>) => ({
  fetchFn: makeFetchMock(responses),
  now: nowFn,
});

describe('buildTrustChain の Trust Anchor 鍵ピン留め', () => {
  it('ピン留め鍵で署名された正規チェーンは成立し anchorPinned: true', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.anchorId, depsOf(topo.responses), {
      trustAnchorJwks: pinnedJwks,
    });
    expect(chain.valid).toBe(true);
    expect(chain.anchorPinned).toBe(true);
  });

  it('未指定なら従来どおり成立し anchorPinned: false（後方互換）', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.anchorId, depsOf(topo.responses));
    expect(chain.valid).toBe(true);
    expect(chain.anchorPinned).toBe(false);
  });

  it('Anchor の自己署名 EC を別鍵に差し替えたチェーンは、ピン留め下で TRUST_CHAIN_INVALID', async () => {
    const forged = forgedAnchorTopology();
    // 前提: ピン留め無しでは偽造チェーンが valid になる（現状の弱点）。
    const unpinned = await buildTrustChain(
      forged.leafId,
      forged.anchorId,
      depsOf(forged.responses),
    );
    expect(unpinned.valid).toBe(true);
    expect(
      await rejectionCode(
        buildTrustChain(forged.leafId, forged.anchorId, depsOf(forged.responses), {
          trustAnchorJwks: pinnedJwks,
        }),
      ),
    ).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('Leaf 自身が Anchor の 1 段チェーンでもピン留めを検査する', async () => {
    const forged = forgedAnchorTopology();
    expect(
      await rejectionCode(
        buildTrustChain(forged.anchorId, forged.anchorId, depsOf(forged.responses), {
          trustAnchorJwks: pinnedJwks,
        }),
      ),
    ).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('ピン留め鍵のいずれにも一致しない（別の正規鍵のみ設定）チェーンは拒否する', async () => {
    const topo = buildValidTopology();
    expect(
      await rejectionCode(
        buildTrustChain(topo.leafId, topo.anchorId, depsOf(topo.responses), {
          trustAnchorJwks: { keys: [toJwk(WRONG_KEY)] },
        }),
      ),
    ).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('ローテーション中（複数のピン留め鍵のうち 1 つが一致）は成立する', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.anchorId, depsOf(topo.responses), {
      trustAnchorJwks: { keys: [toJwk(WRONG_KEY), toJwk(ANCHOR_KEY, 'anchor-1')] },
    });
    expect(chain.anchorPinned).toBe(true);
  });

  it.each([
    ['空の keys', { keys: [] }],
    ['keys が配列でない', { keys: 'x' }],
    ['鍵素材を持たない鍵', { keys: [{ kty: 'EC', kid: 'a' }] }],
    ['null', null],
  ])('不正なピン留め設定（%s）は未指定へ倒さず拒否する', async (_label, jwks) => {
    const topo = buildValidTopology();
    expect(
      await rejectionCode(
        buildTrustChain(topo.leafId, topo.anchorId, depsOf(topo.responses), {
          trustAnchorJwks: jwks as never,
        }),
      ),
    ).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });
});

describe('verifyTrustAnchor の Trust Anchor 鍵ピン留め', () => {
  it('ピン留め鍵で署名された正規チェーンは true', async () => {
    const topo = buildValidTopology();
    expect(
      await verifyTrustAnchor(topo.leafId, topo.anchorId, depsOf(topo.responses), {
        trustAnchorJwks: pinnedJwks,
      }),
    ).toBe(true);
  });

  it('自己署名の偽 Anchor は、ピン留め無しでは true だが、ピン留め下では false', async () => {
    const forged = forgedAnchorTopology();
    expect(await verifyTrustAnchor(forged.leafId, forged.anchorId, depsOf(forged.responses))).toBe(
      true,
    );
    expect(
      await verifyTrustAnchor(forged.leafId, forged.anchorId, depsOf(forged.responses), {
        trustAnchorJwks: pinnedJwks,
      }),
    ).toBe(false);
  });

  it('不正なピン留め設定（空の keys）は未指定へ倒さず false', async () => {
    const topo = buildValidTopology();
    expect(
      await verifyTrustAnchor(topo.leafId, topo.anchorId, depsOf(topo.responses), {
        trustAnchorJwks: { keys: [] },
      }),
    ).toBe(false);
  });
});
