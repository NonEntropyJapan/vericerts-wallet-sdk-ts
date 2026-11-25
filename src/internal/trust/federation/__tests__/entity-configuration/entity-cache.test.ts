/**
 * `toFederationEntityCache` / `createFederationEntityCache` のユニット・統合テスト。
 * 実鍵 P-256 で署名し、`fetch` はモックを使う。
 *
 * 検証内容:
 * - 統合: `buildTrustChain` が返した chain を仕様どおりのフィールドに変換する（順序込み）。
 * - `expiresAt` は「最も早く `exp` を迎えるノード」基準（1 段でも失効すれば chain 全体が不成立）。
 * - `exp` が遠い未来でも TTL 上限 600 秒で頭打ちになる。
 * - ノードの生 JWT が欠落していれば TRUST_CHAIN_INVALID（5010）。欠落を黙って許さない。
 * - キャッシュの get / set / TTL 失効。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import {
  createFederationEntityCache,
  federationEntityCacheTtlSeconds,
  toFederationEntityCache,
} from '../../cache/entity-cache.js';
import { FEDERATION_CACHE_MAX_TTL_SECONDS } from '../../cache/statement-cache.js';
import type { EntityStatement, TrustChain, TrustChainNode } from '../../federation-types.js';
import { buildTrustChain } from '../../trust-chain.js';
import {
  buildValidTopology,
  LEAF_KEY,
  makeFetchMock,
  NOW_SECONDS,
  nowFn,
  signStatement,
  toJwk,
} from '../federation-fixtures.js';

const LEAF_ID = 'https://leaf.example.eu';
const ANCHOR_ID = 'https://anchor.example.eu';

/** ISO 8601 文字列をエポック秒に戻す（期待値との比較用）。 */
function epochSeconds(iso: string): number {
  return Math.floor(Date.parse(iso) / 1000);
}

/**
 * 指定 `exp` を持つ実署名 Entity Statement ノードを組み立てる。
 *
 * @param sub 主体の Entity Identifier。
 * @param exp 失効時刻（エポック秒）。
 * @param withJwt 生 JWT を持たせるか（false で「配線漏れ」ノードを再現する）。
 */
function node(sub: string, exp: number, withJwt = true): TrustChainNode {
  const statement: EntityStatement = {
    iss: sub,
    sub,
    iat: NOW_SECONDS - 3600,
    exp,
    jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
  };
  const jwt = signStatement(LEAF_KEY, { ...statement }, { kid: 'leaf-1' });
  return withJwt
    ? { iss: sub, sub, kind: 'entity-configuration', statement, jwt }
    : { iss: sub, sub, kind: 'entity-configuration', statement };
}

/** 検証済み扱いの TrustChain を組み立てる。 */
function chainOf(nodes: readonly TrustChainNode[]): TrustChain {
  return {
    valid: true,
    leaf: LEAF_ID,
    trustAnchor: ANCHOR_ID,
    nodes,
    length: nodes.length,
    revokedKeys: [],
  };
}

describe('toFederationEntityCache - 正常系（統合: buildTrustChain の戻り値を変換）', () => {
  it('FederationEntityCache のフィールドを chain から組み立てる', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.anchorId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });

    const cached = toFederationEntityCache(chain, NOW_SECONDS);

    expect(cached.entityId).toBe(topo.leafId);
    expect(cached.valid).toBe(true);
    expect(cached.trustAnchors).toEqual([topo.anchorId]);
    // Leaf EC → Sub(Int→Leaf) → Sub(Anchor→Int) → Anchor EC の順で生 JWT が並ぶ。
    expect(cached.trustChain).toEqual([
      topo.responses.get(`${topo.leafId}/.well-known/openid-federation`) as string,
      topo.responses.get(
        `${topo.intermediateId}/fetch?sub=${encodeURIComponent(topo.leafId)}`,
      ) as string,
      topo.responses.get(
        `${topo.anchorId}/fetch?sub=${encodeURIComponent(topo.intermediateId)}`,
      ) as string,
      topo.responses.get(`${topo.anchorId}/.well-known/openid-federation`) as string,
    ]);
    expect(cached.entityConfigurationJwt).toBe(cached.trustChain[0] as string);
    expect(cached.fetchedAt).toBe(new Date(NOW_SECONDS * 1000).toISOString());
    // フィクスチャの exp は NOW+3600 なので、TTL 上限 600 秒が先に効く。
    expect(epochSeconds(cached.expiresAt)).toBe(NOW_SECONDS + FEDERATION_CACHE_MAX_TTL_SECONDS);
  });

  it('Leaf 自身が Trust Anchor の 1 段チェーンも変換できる', async () => {
    const topo = buildValidTopology();
    const chain = await buildTrustChain(topo.leafId, topo.leafId, {
      fetchFn: makeFetchMock(topo.responses),
      now: nowFn,
    });

    const cached = toFederationEntityCache(chain, NOW_SECONDS);

    expect(cached.trustChain).toEqual([
      topo.responses.get(`${topo.leafId}/.well-known/openid-federation`) as string,
    ]);
    expect(cached.entityConfigurationJwt).toBe(cached.trustChain[0] as string);
    expect(cached.trustAnchors).toEqual([topo.leafId]);
  });
});

describe('toFederationEntityCache - expiresAt', () => {
  it('最も早く exp を迎えるノードを基準にする', () => {
    const chain = chainOf([
      node(LEAF_ID, NOW_SECONDS + 3600),
      // このノードが最も早く失効する。chain 全体の寿命はここで決まる。
      node('https://intermediate.example.eu', NOW_SECONDS + 300),
      node(ANCHOR_ID, NOW_SECONDS + 7200),
    ]);

    const cached = toFederationEntityCache(chain, NOW_SECONDS);

    expect(epochSeconds(cached.expiresAt)).toBe(NOW_SECONDS + 300);
  });

  it('全ノードの exp が遠い未来でも TTL 上限（600 秒）で頭打ちになる', () => {
    const farFuture = NOW_SECONDS + 365 * 24 * 3600;
    const chain = chainOf([node(LEAF_ID, farFuture), node(ANCHOR_ID, farFuture)]);

    const cached = toFederationEntityCache(chain, NOW_SECONDS);

    expect(epochSeconds(cached.expiresAt)).toBe(NOW_SECONDS + FEDERATION_CACHE_MAX_TTL_SECONDS);
  });

  it('既に exp を過ぎたノードがあれば TTL 0（fetchedAt と同時刻）になる', () => {
    const chain = chainOf([node(LEAF_ID, NOW_SECONDS + 3600), node(ANCHOR_ID, NOW_SECONDS - 1)]);

    const cached = toFederationEntityCache(chain, NOW_SECONDS);

    expect(cached.expiresAt).toBe(cached.fetchedAt);
  });

  it('maxTtlSeconds を明示指定すると上限をさらに厳しくできる', () => {
    const chain = chainOf([node(LEAF_ID, NOW_SECONDS + 3600), node(ANCHOR_ID, NOW_SECONDS + 3600)]);

    const cached = toFederationEntityCache(chain, NOW_SECONDS, 60);

    expect(epochSeconds(cached.expiresAt)).toBe(NOW_SECONDS + 60);
  });

  it('chain.warnings が設定されている場合（FO-6 由来）は exp に関わらず TTL 0 になる', () => {
    const chain: TrustChain = {
      ...chainOf([node(LEAF_ID, NOW_SECONDS + 3600), node(ANCHOR_ID, NOW_SECONDS + 3600)]),
      warnings: [{ policyEvent: 'FO-6', auditEvent: 'federation_fetch_failed_cache_ok' }],
    };

    const cached = toFederationEntityCache(chain, NOW_SECONDS);

    // 同意・監査・60 秒ウィンドウをバイパスしたまま最大 600 秒再利用されるのを防ぐため、
    // FO-6 の警告が付いた chain は fetchedAt と同時刻（TTL 0）で必ず即座に期限切れにする。
    expect(cached.expiresAt).toBe(cached.fetchedAt);
  });
});

describe('toFederationEntityCache - 生 JWT の欠落', () => {
  it('中間ノードの jwt が欠落していれば TRUST_CHAIN_INVALID', () => {
    const chain = chainOf([
      node(LEAF_ID, NOW_SECONDS + 3600),
      node('https://intermediate.example.eu', NOW_SECONDS + 3600, false),
      node(ANCHOR_ID, NOW_SECONDS + 3600),
    ]);

    let caught: unknown;
    try {
      toFederationEntityCache(chain, NOW_SECONDS);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('Leaf ノードの jwt が欠落していれば TRUST_CHAIN_INVALID', () => {
    const chain = chainOf([node(LEAF_ID, NOW_SECONDS + 3600, false)]);

    expect(() => toFederationEntityCache(chain, NOW_SECONDS)).toThrow(VericertsError);
  });
});

describe('createFederationEntityCache', () => {
  it('set した値を TTL 内は取得でき、TTL 超過後は expired になる', () => {
    let now = NOW_SECONDS;
    const cache = createFederationEntityCache(() => now);
    const chain = chainOf([node(LEAF_ID, NOW_SECONDS + 3600), node(ANCHOR_ID, NOW_SECONDS + 3600)]);
    const cached = toFederationEntityCache(chain, now);

    cache.set(cached.entityId, cached, 300);
    expect(cache.get(cached.entityId)?.value).toEqual(cached);
    expect(cache.get(cached.entityId)?.expired).toBe(false);

    now += 299;
    expect(cache.get(cached.entityId)?.expired).toBe(false);

    now += 2;
    expect(cache.get(cached.entityId)?.expired).toBe(true);
  });

  it('未登録キーは undefined を返す', () => {
    const cache = createFederationEntityCache(() => NOW_SECONDS);
    expect(cache.get('https://unknown.example.eu')).toBeUndefined();
  });

  it('TTL 上限 600 秒を超える TTL 指定は切り詰められる', () => {
    let now = NOW_SECONDS;
    const cache = createFederationEntityCache(() => now);
    const chain = chainOf([node(LEAF_ID, NOW_SECONDS + 3600), node(ANCHOR_ID, NOW_SECONDS + 3600)]);
    const cached = toFederationEntityCache(chain, now);

    cache.set(cached.entityId, cached, 3600);

    now += FEDERATION_CACHE_MAX_TTL_SECONDS;
    expect(cache.get(cached.entityId)?.expired).toBe(true);
  });
});

describe('federationEntityCacheTtlSeconds', () => {
  it('FO-6 由来 chain（warnings 付き）は cache.set に実際に保存しても再利用可能な形で残らない', () => {
    const now = NOW_SECONDS;
    const cache = createFederationEntityCache(() => now);
    const chain: TrustChain = {
      ...chainOf([node(LEAF_ID, NOW_SECONDS + 3600), node(ANCHOR_ID, NOW_SECONDS + 3600)]),
      warnings: [{ policyEvent: 'FO-6', auditEvent: 'federation_fetch_failed_cache_ok' }],
    };
    const cached = toFederationEntityCache(chain, now);

    const ttl = federationEntityCacheTtlSeconds(cached, now);
    expect(ttl).toBe(0);

    // 推奨呼び出しパターンどおり、逆算した TTL をそのまま cache.set に渡す。
    cache.set(cached.entityId, cached, ttl, now);

    // TTL 0 は `TtlCache.set` の no-store 相当（ttl-cache.ts）であり、格納済みの値が有れば削除する。
    // したがって同時刻の取得は `undefined`（expired なエントリとしてすら残らない）。
    // 同意・監査・60 秒ウィンドウをバイパスしたまま最大 600 秒再利用されることを防ぐ。
    expect(cache.get(cached.entityId, now)).toBeUndefined();
  });

  it('通常の chain（warnings 無し）は cache.set に保存すると通常の TTL（600 秒）で有効になる', () => {
    let now = NOW_SECONDS;
    const cache = createFederationEntityCache(() => now);
    const chain = chainOf([node(LEAF_ID, NOW_SECONDS + 3600), node(ANCHOR_ID, NOW_SECONDS + 3600)]);
    const cached = toFederationEntityCache(chain, now);

    const ttl = federationEntityCacheTtlSeconds(cached, now);
    expect(ttl).toBe(FEDERATION_CACHE_MAX_TTL_SECONDS);

    cache.set(cached.entityId, cached, ttl, now);

    expect(cache.get(cached.entityId, now)?.expired).toBe(false);

    now += FEDERATION_CACHE_MAX_TTL_SECONDS - 1;
    expect(cache.get(cached.entityId, now)?.expired).toBe(false);

    now += 1;
    expect(cache.get(cached.entityId, now)?.expired).toBe(true);
  });
});
