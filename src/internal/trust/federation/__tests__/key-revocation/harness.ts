/**
 * 鍵無効化宣言（`revoked_keys`）の Trust Chain 検証テスト用の共有トポロジビルダ。
 *
 * Issuer 鍵の漏洩からの復旧を検証する。実鍵 P-256 で署名し、`fetch` はモックを使う。
 *
 * テストケースは含まない（Linterly の 1 ファイル 300 行上限に収めるための分離）。
 */

import { expect } from 'bun:test';
import { type ErrorCode, VericertsError } from '../../../../errors.js';
import {
  ANCHOR_KEY,
  LEAF_KEY,
  makeFetchMock,
  NOW_SECONDS,
  nowFn,
  signStatement,
  toJwk,
} from '../federation-fixtures.js';

/** 漏洩鍵の kid（Leaf が現に Entity Configuration で主張している鍵）。 */
export const LEAF_KID = 'leaf-1';

/** 無効化時刻 T（この時刻以降に発行された署名を拒否する）。`now` より前に置く。 */
export const REVOKED_AT = NOW_SECONDS - 1800;

export const LEAF_ID = 'https://leaf.example.eu';
export const ANCHOR_ID = 'https://anchor.example.eu';
export const ANCHOR_FETCH = `${ANCHOR_ID}/fetch`;

/** 鍵漏洩宣言（Leaf が現に EC で主張している鍵を T で無効化）。 */
export const COMPROMISE_DECLARATION = [
  { kid: LEAF_KID, revoked_at: REVOKED_AT, reason: 'key_compromise' },
];

/**
 * ローテートで EC から外された旧鍵の `kid`。
 *
 * 漏洩後に鍵をローテートした正当なエンティティは、新しい鍵だけを載せた Entity Configuration を
 * publish する。宣言は旧鍵に残るがチェーン構築は妨げない一方、旧鍵で署名された VC には効き続ける
 * ——この分業（Statement は `now` 基準 / VC は `iat` 基準）を検証するための構成である。
 */
export const ROTATED_OUT_KID = 'leaf-0';

/** ローテート済みの旧鍵についての宣言。Leaf の現行 EC には載っていないためチェーンは成立する。 */
export const ROTATED_DECLARATION = [
  { kid: ROTATED_OUT_KID, revoked_at: REVOKED_AT, reason: 'key_compromise' },
];

/** reject が指定コードの VericertsError であることを検証し、その例外を返す。 */
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
  expect((caught as VericertsError).code).toBe(code);
  return caught as VericertsError;
}

/**
 * Leaf → Anchor の 2 段トポロジを組み立てる。
 *
 * Trust Anchor が Leaf についての Subordinate Statement を発行し、任意で `revoked_keys` を載せる。
 *
 * @param leafIat Leaf Entity Configuration の `iat`（エポック秒）。
 * @param revokedKeys Subordinate Statement に載せる `revoked_keys`（未指定なら載せない）。
 */
export function buildTopology(leafIat: number, revokedKeys?: unknown): Map<string, string> {
  const leafJwks = { keys: [toJwk(LEAF_KEY, LEAF_KID)] };
  const anchorJwks = { keys: [toJwk(ANCHOR_KEY, 'anchor-1')] };

  const leafEc = signStatement(
    LEAF_KEY,
    {
      iss: LEAF_ID,
      sub: LEAF_ID,
      iat: leafIat,
      exp: NOW_SECONDS + 3600,
      jwks: leafJwks,
      authority_hints: [ANCHOR_ID],
    },
    { kid: LEAF_KID },
  );
  const anchorEc = signStatement(
    ANCHOR_KEY,
    {
      iss: ANCHOR_ID,
      sub: ANCHOR_ID,
      iat: NOW_SECONDS - 3600,
      exp: NOW_SECONDS + 3600,
      jwks: anchorJwks,
      metadata: { federation_entity: { federation_fetch_endpoint: ANCHOR_FETCH } },
    },
    { kid: 'anchor-1' },
  );
  const anchorAboutLeaf = signStatement(ANCHOR_KEY, {
    iss: ANCHOR_ID,
    sub: LEAF_ID,
    iat: NOW_SECONDS - 3600,
    exp: NOW_SECONDS + 3600,
    jwks: leafJwks,
    ...(revokedKeys === undefined ? {} : { revoked_keys: revokedKeys }),
  });

  const responses = new Map<string, string>();
  responses.set(`${LEAF_ID}/.well-known/openid-federation`, leafEc);
  responses.set(`${ANCHOR_ID}/.well-known/openid-federation`, anchorEc);
  responses.set(`${ANCHOR_FETCH}?sub=${encodeURIComponent(LEAF_ID)}`, anchorAboutLeaf);
  return responses;
}

/** トポロジから `buildTrustChain` の依存注入を組み立てる。 */
export function deps(responses: Map<string, string>): { fetchFn: typeof fetch; now: () => number } {
  return { fetchFn: makeFetchMock(responses), now: nowFn };
}
