/**
 * `TrustChain.warnings`（FO-6 のチェーン単位集約）の回帰テスト。
 *
 * 検証内容:
 * - FO-6 が 1 件も起きなければ `warnings` は**未設定**（空配列ではない）。
 * - Leaf / 中間ノードのどちらの Entity Configuration で FO-6 が成立しても集約され、チェーン自体は
 *   成立する（stale な実データを通常どおり検証して組み上げているため）。
 * - **Trust Anchor 自身**の Entity Configuration は FO-6 の対象外。
 *   Trust Anchor の鍵には Subordinate Statement の `revoked_keys` に相当する無効化経路（FC-11）が
 *   存在しないため、stale なアンカー EC を FO-6 で受理すると漏洩鍵での署名検証を許してしまう。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import type { BuildTrustChainDeps } from '../../trust-chain.js';
import { buildTrustChain } from '../../trust-chain.js';
import {
  buildValidTopology,
  LEAF_KEY,
  NOW_SECONDS,
  signStatement,
  toJwk,
} from '../federation-fixtures.js';
import {
  expectRejectCode,
  type FailOpenHarness,
  FO6_WARNING,
  failOpenHarness,
  STALE_AFTER_SECONDS,
} from './harness.js';

const TOPOLOGY = buildValidTopology();

/** well-known URL（Entity Configuration の取得先）を返す。 */
function wellKnown(entityId: string): string {
  return `${entityId}/.well-known/openid-federation`;
}

/**
 * チェーンを 1 度構築してキャッシュを温め、TTL 切れまで進めてから指定 URL だけ停止させる。
 *
 * @param offlineUrl 503 を返させる URL（省略時はすべて到達可能なまま）。
 */
async function primed(offlineUrl?: string): Promise<FailOpenHarness> {
  const h = failOpenHarness(TOPOLOGY.responses);
  await buildTrustChain(TOPOLOGY.leafId, TOPOLOGY.anchorId, h.base);
  h.advance(STALE_AFTER_SECONDS);
  if (offlineUrl !== undefined) {
    h.goOffline((url) => url === offlineUrl);
  }
  return h;
}

/** FO-6 を有効にした依存注入を組み立てる。 */
function failOpenDeps(h: FailOpenHarness): BuildTrustChainDeps {
  return {
    ...h.base,
    failOpenWindow: createFailOpenWindow(),
    onPolicyEvent: h.onPolicyEvent,
    requestConsent: h.requestConsent,
  };
}

describe('TrustChain.warnings', () => {
  it('FO-6 が起きなければ未設定のまま（空配列を返さない）', async () => {
    const h = await primed();
    const chain = await buildTrustChain(TOPOLOGY.leafId, TOPOLOGY.anchorId, failOpenDeps(h));
    expect(chain.valid).toBe(true);
    expect(chain.warnings).toBeUndefined();
    expect(h.records).toEqual([]);
  });

  it('Leaf の Entity Configuration で FO-6 が成立すれば集約され、チェーンは成立する', async () => {
    const h = await primed(wellKnown(TOPOLOGY.leafId));
    const chain = await buildTrustChain(TOPOLOGY.leafId, TOPOLOGY.anchorId, failOpenDeps(h));
    expect(chain.valid).toBe(true);
    expect(chain.warnings).toEqual([FO6_WARNING]);
    expect(chain.nodes[0]?.sub).toBe(TOPOLOGY.leafId);
    expect(h.records).toHaveLength(1);
  });

  it('中間ノードの Entity Configuration で FO-6 が成立しても同様に集約する', async () => {
    const h = await primed(wellKnown(TOPOLOGY.intermediateId));
    const chain = await buildTrustChain(TOPOLOGY.leafId, TOPOLOGY.anchorId, failOpenDeps(h));
    expect(chain.valid).toBe(true);
    expect(chain.warnings).toEqual([FO6_WARNING]);
    expect(chain.trustAnchor).toBe(TOPOLOGY.anchorId);
  });
});

describe('Trust Anchor 自身の Entity Configuration は FO-6 の対象外', () => {
  it('アンカーの EC が stale でもオフラインなら Fail-open せず 5011 を伝播する（多段チェーン）', async () => {
    const h = await primed(wellKnown(TOPOLOGY.anchorId));
    await expectRejectCode(
      buildTrustChain(TOPOLOGY.leafId, TOPOLOGY.anchorId, failOpenDeps(h)),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    // アンカーの取得失敗は FO-6 のゲートを一切通らないため監査記録も残らない。
    expect(h.records).toEqual([]);
  });

  it('Leaf 自身が Trust Anchor の退化ケースでも Fail-open せず 5011 を伝播する', async () => {
    const selfAnchorId = 'https://self-anchor.example.eu';
    const wellKnownUrl = wellKnown(selfAnchorId);
    const selfSigned = signStatement(
      LEAF_KEY,
      {
        iss: selfAnchorId,
        sub: selfAnchorId,
        iat: NOW_SECONDS - 3600,
        exp: NOW_SECONDS + 4000,
        jwks: { keys: [toJwk(LEAF_KEY, 'self-anchor-1')] },
      },
      { kid: 'self-anchor-1' },
    );
    const h = failOpenHarness(new Map([[wellKnownUrl, selfSigned]]));
    await buildTrustChain(selfAnchorId, selfAnchorId, h.base);
    h.advance(STALE_AFTER_SECONDS);
    h.goOffline();
    await expectRejectCode(
      buildTrustChain(selfAnchorId, selfAnchorId, failOpenDeps(h)),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    expect(h.records).toEqual([]);
  });
});
