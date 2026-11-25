/**
 * 鍵無効化宣言のスコープ回帰テスト用の共有トポロジビルダ。
 *
 * `federation-fixtures.ts` の `buildValidTopology` は固定構成のため、`kid` の衝突や
 * `iat` の前後関係を個別に操作できない。本ヘルパはそれらをパラメータ化した 3 段チェーン
 * （Leaf → Intermediate → Anchor）を組み立てる。
 *
 * テストケースは含まない（Linterly の 1 ファイル 300 行上限に収めるための分離）。
 */

import { expect } from 'bun:test';
import { type ErrorCode, VericertsError } from '../../../../errors.js';
import type { BuildTrustChainDeps } from '../../trust-chain.js';
import {
  ANCHOR_KEY,
  INTERMEDIATE_KEY,
  LEAF_KEY,
  makeFetchMock,
  NOW_SECONDS,
  nowFn,
  signStatement,
  toJwk,
} from '../federation-fixtures.js';

export const LEAF_ID = 'https://leaf.example.eu';
export const INTERMEDIATE_ID = 'https://intermediate.example.eu';
export const ANCHOR_ID = 'https://anchor.example.eu';

const INT_FETCH = `${INTERMEDIATE_ID}/fetch`;
const ANCHOR_FETCH = `${ANCHOR_ID}/fetch`;

/** 無効化時刻 T（この時刻以降に発行された署名を拒否する）。 */
export const REVOKED_AT = NOW_SECONDS - 1800;

/** 3 段トポロジの可変パラメータ。 */
export interface TopologyOptions {
  /** Leaf の鍵 `kid`。 */
  readonly leafKid: string;
  /** Intermediate の鍵 `kid`。 */
  readonly intermediateKid: string;
  /** Leaf の Entity Configuration の `iat`。 */
  readonly leafIat: number;
  /** Intermediate の Entity Configuration の `iat`。 */
  readonly intermediateIat: number;
  /** Intermediate → Leaf の Subordinate Statement の `iat`。 */
  readonly intAboutLeafIat: number;
  /** Anchor → Intermediate の Subordinate Statement に載せる `revoked_keys`。 */
  readonly anchorRevokedKeys?: unknown;
}

/** `exp` は常に NOW より先に置く（有効期間切れで落ちないように）。 */
function period(iat: number): { iat: number; exp: number } {
  return { iat, exp: NOW_SECONDS + 3600 };
}

/**
 * パラメータ化した 3 段チェーンの URL → JWT マップを構築する。
 *
 * @param opts `kid` と `iat` の構成、および Anchor が出す `revoked_keys`。
 * @returns `buildTrustChain` に渡せる依存注入。
 */
export function topologyDeps(opts: TopologyOptions): BuildTrustChainDeps {
  const leafJwks = { keys: [toJwk(LEAF_KEY, opts.leafKid)] };
  const intermediateJwks = { keys: [toJwk(INTERMEDIATE_KEY, opts.intermediateKid)] };
  const anchorJwks = { keys: [toJwk(ANCHOR_KEY, 'anchor-1')] };

  const leafEc = signStatement(
    LEAF_KEY,
    {
      iss: LEAF_ID,
      sub: LEAF_ID,
      ...period(opts.leafIat),
      jwks: leafJwks,
      authority_hints: [INTERMEDIATE_ID],
    },
    { kid: opts.leafKid },
  );
  const intermediateEc = signStatement(
    INTERMEDIATE_KEY,
    {
      iss: INTERMEDIATE_ID,
      sub: INTERMEDIATE_ID,
      ...period(opts.intermediateIat),
      jwks: intermediateJwks,
      authority_hints: [ANCHOR_ID],
      metadata: { federation_entity: { federation_fetch_endpoint: INT_FETCH } },
    },
    { kid: opts.intermediateKid },
  );
  const anchorEc = signStatement(
    ANCHOR_KEY,
    {
      iss: ANCHOR_ID,
      sub: ANCHOR_ID,
      ...period(NOW_SECONDS - 3600),
      jwks: anchorJwks,
      metadata: { federation_entity: { federation_fetch_endpoint: ANCHOR_FETCH } },
    },
    { kid: 'anchor-1' },
  );

  // Intermediate が Leaf について出す Subordinate Statement（Intermediate の鍵で署名）。
  const intAboutLeaf = signStatement(
    INTERMEDIATE_KEY,
    {
      iss: INTERMEDIATE_ID,
      sub: LEAF_ID,
      ...period(opts.intAboutLeafIat),
      jwks: leafJwks,
    },
    { kid: opts.intermediateKid },
  );
  // Anchor が Intermediate について出す Subordinate Statement（Anchor の鍵で署名）。
  const anchorAboutInt = signStatement(
    ANCHOR_KEY,
    {
      iss: ANCHOR_ID,
      sub: INTERMEDIATE_ID,
      ...period(NOW_SECONDS - 3600),
      jwks: intermediateJwks,
      ...(opts.anchorRevokedKeys === undefined ? {} : { revoked_keys: opts.anchorRevokedKeys }),
    },
    { kid: 'anchor-1' },
  );

  const responses = new Map<string, string>([
    [`${LEAF_ID}/.well-known/openid-federation`, leafEc],
    [`${INTERMEDIATE_ID}/.well-known/openid-federation`, intermediateEc],
    [`${ANCHOR_ID}/.well-known/openid-federation`, anchorEc],
    [`${INT_FETCH}?sub=${encodeURIComponent(LEAF_ID)}`, intAboutLeaf],
    [`${ANCHOR_FETCH}?sub=${encodeURIComponent(INTERMEDIATE_ID)}`, anchorAboutInt],
  ]);
  return { fetchFn: makeFetchMock(responses), now: nowFn };
}

/** reject が指定コードの VericertsError であることを検証する。 */
export async function expectRejectCode(
  promise: Promise<unknown>,
  code: ErrorCode,
): Promise<VericertsError> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  const failure = caught as VericertsError;
  expect(failure.code).toBe(code);
  return failure;
}
