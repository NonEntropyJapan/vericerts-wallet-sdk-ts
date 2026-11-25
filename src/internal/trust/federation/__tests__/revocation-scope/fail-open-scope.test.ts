/**
 * FO-6 を有効にしても Subordinate Statement 経路と FC-11 が緩まないことの回帰テスト。
 *
 * FO-6 と鍵無効化宣言の境界を固定する。
 *
 * FO-6 のオプション（`failOpenWindow` / `onPolicyEvent` / `requestConsent`）は
 * `ResolveEntityConfigurationDeps` に生えており、`verifySubordinate` は**同じ deps を受け取る**。
 * したがって「フィールドがそこにある」だけで Subordinate Statement の取得失敗まで stale キャッシュで
 * 救われないことを、型ではなく挙動で固定しておく必要がある。救われてしまうと、鍵漏洩後に上位が
 * 公開した `revoked_keys` を含まない古い Statement を無期限に再利用でき、FC-11 が空振りする。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import type { FailSafeAuditRecord } from '../../../../failsafe-policy/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { createFederationStatementCache } from '../../cache/statement-cache.js';
import type { BuildTrustChainDeps } from '../../trust-chain.js';
import { buildTrustChain } from '../../trust-chain.js';
import { NOW_SECONDS } from '../federation-fixtures.js';
import {
  ANCHOR_ID,
  expectRejectCode,
  LEAF_ID,
  REVOKED_AT,
  type TopologyOptions,
  topologyDeps,
} from './harness.js';

/** キャッシュ TTL 上限（600 秒）を確実に超える前進量。`exp`（NOW + 3600）は超えない。 */
const STALE_AFTER_SECONDS = 700;

/** well-known URL（Entity Configuration の取得先）。 */
function wellKnown(entityId: string): string {
  return `${entityId}/.well-known/openid-federation`;
}

/** FO-6 を全面的に有効にした deps と、その観測点。 */
function failOpenDeps(options: TopologyOptions) {
  let now = NOW_SECONDS;
  let offlineFor: ((url: string) => boolean) | undefined;
  const records: FailSafeAuditRecord[] = [];
  const base = topologyDeps(options);
  const online = base.fetchFn as typeof fetch;
  const deps: BuildTrustChainDeps = {
    fetchFn: (async (input: string | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString();
      if (offlineFor?.(url) === true) {
        return new Response('unavailable', { status: 503 });
      }
      return online(url);
    }) as typeof fetch,
    now: (): number => now * 1000,
    statementCache: createFederationStatementCache(() => now),
    failOpenWindow: createFailOpenWindow(),
    onPolicyEvent: (record: FailSafeAuditRecord): void => {
      records.push(record);
    },
    requestConsent: (): boolean => true,
  };
  return {
    deps,
    records,
    /** チェーンを 1 度構築してキャッシュを温め、TTL 切れまで進めて対象 URL を停止させる。 */
    prime: async (offlineUrl: (url: string) => boolean): Promise<void> => {
      await buildTrustChain(LEAF_ID, ANCHOR_ID, deps).catch(() => undefined);
      now += STALE_AFTER_SECONDS;
      offlineFor = offlineUrl;
    },
  };
}

/** 署名・鍵ともに健全な 3 段チェーン（宣言なし）。 */
const HEALTHY: TopologyOptions = {
  leafKid: 'leaf-1',
  intermediateKid: 'int-1',
  leafIat: NOW_SECONDS - 3600,
  intermediateIat: NOW_SECONDS - 3600,
  intAboutLeafIat: NOW_SECONDS - 3600,
};

/** Anchor が Intermediate の `int-1` を失効させ、その鍵で Subordinate Statement を発行した構成。 */
const REVOKED: TopologyOptions = {
  leafKid: 'leaf-1',
  intermediateKid: 'int-1',
  leafIat: NOW_SECONDS - 3600,
  intermediateIat: REVOKED_AT - 100,
  intAboutLeafIat: REVOKED_AT + 60,
  anchorRevokedKeys: [{ kid: 'int-1', revoked_at: REVOKED_AT, reason: 'key_compromise' }],
};

describe('FO-6 は Subordinate Statement 経路に及ばない', () => {
  it('Subordinate Statement の取得失敗は stale キャッシュがあっても 5011 のまま', async () => {
    const h = failOpenDeps(HEALTHY);
    // Subordinate Statement の取得 URL は `?sub=` を持つ（Entity Configuration は持たない）。
    await h.prime((url) => url.includes('?sub='));
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, h.deps),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
    // `resolveFailOpen` にすら到達していない（FO-6 の監査記録が 1 件も無い）。
    expect(h.records).toEqual([]);
  });
});

describe('FO-6 が成立した chain でも FC-11 は空振りしない', () => {
  it('Leaf の EC を FO-6 で通しても鍵無効化宣言は 5012 で拒否する', async () => {
    const h = failOpenDeps(REVOKED);
    await h.prime((url) => url === wellKnown(LEAF_ID));
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, h.deps),
      ErrorCodes.FEDERATION_KEY_REVOKED,
    );
    // FO-6 は実際に成立している（＝ 5012 が「FO-6 が働かなかったから」ではない）。
    expect(h.records.map((record) => record.policy_event)).toEqual(['FO-6']);
  });
});
