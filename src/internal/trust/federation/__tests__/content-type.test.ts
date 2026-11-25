/**
 * Entity Statement 応答の Content-Type 検査の回帰テスト。
 *
 * 仕様 SoT: OpenID Federation 1.0 §9（Entity Configuration）・§8（Fetch）。
 *
 * `entity-configuration.ts` と `subordinate.ts` は同じ Entity Statement を同じ `fetchFn` seam から
 * 取る双子の経路であり、どちらも `Accept` で受け入れる型を宣言している。検査が片方にしか無い状態
 * （`subordinate.ts` 側の取りこぼし）に戻らないよう、両経路を同じ観点で押さえる。
 *
 * 検証内容:
 * - `text/html` を返す応答は Entity Configuration / Subordinate Statement のどちらでも
 *   `FEDERATION_FETCH_FAILED`（5011）に倒れる。
 * - Content-Type 欠落は両経路とも許容する（本体は JWT 署名で検証する）。
 * - `charset` 等のパラメータ付きは両経路とも許容する。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import { resolveEntityConfiguration } from '../entity-configuration.js';
import type { JsonWebKeySet } from '../federation-types.js';
import { verifySubordinate } from '../subordinate.js';
import {
  buildValidTopology,
  LEAF_KEY,
  makeFetchMock,
  NOW_SECONDS,
  nowFn,
  toJwk,
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

/**
 * 指定 URL だけ Content-Type を差し替える `fetch` モックを生成する。
 *
 * `contentType` が `undefined` のときはヘッダ自体を付けない（本文は Uint8Array で渡す。
 * 文字列本文だと Response が `text/plain` を自動付与してしまい「欠落」を再現できない）。
 */
function fetchMockWithContentType(
  responses: ReadonlyMap<string, string>,
  targetUrl: string,
  contentType: string | undefined,
): typeof fetch {
  const fallback = makeFetchMock(new Map(responses));
  return (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const jwt = responses.get(url);
    if (url !== targetUrl || jwt === undefined) {
      return fallback(input as string, init);
    }
    if (contentType === undefined) {
      return new Response(new TextEncoder().encode(jwt), { status: 200 });
    }
    return new Response(jwt, { status: 200, headers: { 'content-type': contentType } });
  }) as typeof fetch;
}

const LEAF_JWKS: JsonWebKeySet = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };

/** Intermediate の検証済み Entity Configuration（Subordinate 取得の parent）を用意する。 */
async function intermediateConfig(topo: ReturnType<typeof buildValidTopology>) {
  return resolveEntityConfiguration(topo.intermediateId, {
    fetchFn: makeFetchMock(topo.responses),
    now: nowFn,
  });
}

/** Intermediate が Leaf について発行する Subordinate Statement の取得 URL。 */
function subordinateUrl(topo: ReturnType<typeof buildValidTopology>): string {
  return `${topo.intermediateId}/fetch?sub=${encodeURIComponent(topo.leafId)}`;
}

describe('Subordinate Statement の Content-Type 検査', () => {
  it('text/html を返す応答は FEDERATION_FETCH_FAILED に倒れる', async () => {
    const topo = buildValidTopology();
    const parent = await intermediateConfig(topo);
    const fetchFn = fetchMockWithContentType(topo.responses, subordinateUrl(topo), 'text/html');
    await expectRejectCode(
      verifySubordinate(parent, topo.leafId, LEAF_JWKS, NOW_SECONDS, { fetchFn }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });

  it('Content-Type 欠落は許容する', async () => {
    const topo = buildValidTopology();
    const parent = await intermediateConfig(topo);
    const fetchFn = fetchMockWithContentType(topo.responses, subordinateUrl(topo), undefined);
    const verified = await verifySubordinate(parent, topo.leafId, LEAF_JWKS, NOW_SECONDS, {
      fetchFn,
    });
    expect(verified.statement.sub).toBe(topo.leafId);
  });

  it('charset 付きの application/jwt は許容する', async () => {
    const topo = buildValidTopology();
    const parent = await intermediateConfig(topo);
    const fetchFn = fetchMockWithContentType(
      topo.responses,
      subordinateUrl(topo),
      'application/jwt; charset=utf-8',
    );
    const verified = await verifySubordinate(parent, topo.leafId, LEAF_JWKS, NOW_SECONDS, {
      fetchFn,
    });
    expect(verified.statement.sub).toBe(topo.leafId);
  });
});

describe('Entity Configuration の Content-Type 検査（双子の片側）', () => {
  it('text/html を返す応答は FEDERATION_FETCH_FAILED に倒れる', async () => {
    const topo = buildValidTopology();
    const wellKnown = `${topo.leafId}/.well-known/openid-federation`;
    const fetchFn = fetchMockWithContentType(topo.responses, wellKnown, 'text/html');
    await expectRejectCode(
      resolveEntityConfiguration(topo.leafId, { fetchFn, now: nowFn }),
      ErrorCodes.FEDERATION_FETCH_FAILED,
    );
  });

  it('Content-Type 欠落は許容する', async () => {
    const topo = buildValidTopology();
    const wellKnown = `${topo.leafId}/.well-known/openid-federation`;
    const fetchFn = fetchMockWithContentType(topo.responses, wellKnown, undefined);
    const config = await resolveEntityConfiguration(topo.leafId, { fetchFn, now: nowFn });
    expect(config.entityId).toBe(topo.leafId);
  });
});
