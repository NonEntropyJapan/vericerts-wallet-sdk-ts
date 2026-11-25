/**
 * Entity Statement のクレーム受理範囲とエラーコード分類の回帰テスト。
 *
 * 検証内容:
 * - `iat` / `exp` は非負整数の NumericDate のみ受理する。非整数を通すと、キャッシュ未注入なら
 *   成立する Statement が `statementCache` を注入した途端 `TtlCache.set` の整数 assert に当たって
 *   `3002` で落ちる（キャッシュの有無で検証結果が変わる）。**キャッシュ注入は検証結果を変えない**
 *   ことを両経路で確認する。
 * - Subordinate Statement の**取得**失敗は `5011 FEDERATION_FETCH_FAILED`、**検証**失敗は
 *   `5010 TRUST_CHAIN_INVALID`。negative cache の対象は取得失敗の 5011 に限られている。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { createFederationStatementCache } from '../../cache/statement-cache.js';
import { resolveEntityConfiguration } from '../../entity-configuration.js';
import { buildTrustChain } from '../../trust-chain.js';
import {
  LEAF_KEY,
  makeFetchMock,
  NOW_SECONDS,
  nowFn,
  signStatement,
  toJwk,
} from '../federation-fixtures.js';
import { ANCHOR_ID, expectRejectCode, LEAF_ID, topologyDeps } from './harness.js';

const WELL_KNOWN = `${LEAF_ID}/.well-known/openid-federation`;

/** 指定した有効期間クレームを持つ Leaf の Entity Configuration を配信する依存注入を作る。 */
function leafConfigDeps(period: { iat: number; exp: number }): {
  fetchFn: typeof fetch;
  now: () => number;
} {
  const jwks = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };
  const jwt = signStatement(
    LEAF_KEY,
    { iss: LEAF_ID, sub: LEAF_ID, ...period, jwks },
    { kid: 'leaf-1' },
  );
  return { fetchFn: makeFetchMock(new Map([[WELL_KNOWN, jwt]])), now: nowFn };
}

describe('iat / exp は整数の NumericDate のみ受理する', () => {
  // 非整数 exp。NOW との差が TTL に渡ると TtlCache.set の整数 assert（3002）に当たる。
  const fractionalExp = { iat: NOW_SECONDS - 3600, exp: NOW_SECONDS + 120.5 };

  it('非整数の exp は TRUST_CHAIN_INVALID（5010）で拒否する（キャッシュ未注入）', async () => {
    await expectRejectCode(
      resolveEntityConfiguration(LEAF_ID, leafConfigDeps(fractionalExp)),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  // 回帰の中心: 以前はキャッシュ注入時のみ 3002 が飛び、注入の有無で結果が変わっていた。
  it('キャッシュを注入しても同じ 5010 になる（注入が検証結果を変えない）', async () => {
    const deps = {
      ...leafConfigDeps(fractionalExp),
      statementCache: createFederationStatementCache(() => NOW_SECONDS),
    };
    await expectRejectCode(
      resolveEntityConfiguration(LEAF_ID, deps),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('非整数の iat も 5010 で拒否する', async () => {
    await expectRejectCode(
      resolveEntityConfiguration(
        LEAF_ID,
        leafConfigDeps({ iat: NOW_SECONDS - 3600.5, exp: NOW_SECONDS + 3600 }),
      ),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('整数の iat / exp は従来どおり受理する', async () => {
    const config = await resolveEntityConfiguration(
      LEAF_ID,
      leafConfigDeps({ iat: NOW_SECONDS - 3600, exp: NOW_SECONDS + 3600 }),
    );
    expect(config.entityId).toBe(LEAF_ID);
  });
});

describe('Subordinate Statement のエラーコード分類', () => {
  /** 正常なトポロジから Subordinate Statement の取得だけを 404 にする。 */
  function missingSubordinateDeps(): { fetchFn: typeof fetch; now: () => number } {
    const base = topologyDeps({
      leafKid: 'leaf-1',
      intermediateKid: 'int-1',
      leafIat: NOW_SECONDS - 3600,
      intermediateIat: NOW_SECONDS - 3600,
      intAboutLeafIat: NOW_SECONDS - 3600,
    });
    const inner = base.fetchFn as typeof fetch;
    const fetchFn = (async (input: string | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString();
      // fetch endpoint（`?sub=` を含む URL）だけを取得失敗させる。
      if (url.includes('/fetch?sub=')) {
        return new Response('not found', { status: 404 });
      }
      return inner(input as string);
    }) as typeof fetch;
    return { fetchFn, now: nowFn };
  }

  it('取得（transport）失敗は FEDERATION_FETCH_FAILED（5011）', async () => {
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, missingSubordinateDeps()),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });

  it('取得は成功するが jwks が child の主張と食い違う場合は TRUST_CHAIN_INVALID（5010）', async () => {
    // Leaf の EC と Subordinate Statement で `kid` が食い違う（jwks 不一致）構成。
    const base = topologyDeps({
      leafKid: 'leaf-1',
      intermediateKid: 'int-1',
      leafIat: NOW_SECONDS - 3600,
      intermediateIat: NOW_SECONDS - 3600,
      intAboutLeafIat: NOW_SECONDS - 3600,
    });
    const mismatched = topologyDeps({
      leafKid: 'leaf-2',
      intermediateKid: 'int-1',
      leafIat: NOW_SECONDS - 3600,
      intermediateIat: NOW_SECONDS - 3600,
      intAboutLeafIat: NOW_SECONDS - 3600,
    });
    const fetchFn = (async (input: string | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString();
      // Subordinate Statement だけ別トポロジ（別 kid の jwks を保証するもの）を返す。
      const source = url.includes('/fetch?sub=') ? mismatched.fetchFn : base.fetchFn;
      return (source as typeof fetch)(input as string);
    }) as typeof fetch;
    await expectRejectCode(
      buildTrustChain(LEAF_ID, ANCHOR_ID, { fetchFn, now: nowFn }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });
});
