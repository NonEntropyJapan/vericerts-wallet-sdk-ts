/**
 * OpenID Federation テスト用フィクスチャ（実鍵 P-256、モック署名禁止）。
 *
 * Entity Statement（Entity Configuration / Subordinate Statement）を実際の ES256 署名で
 * 組み立て、`fetch` を差し替えるモックレスポンダを提供する。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, signP256 } from '../../../keymanager/signer.js';

/** base64url（パディングなし）エンコード。 */
export function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** 非圧縮 P-256 公開鍵から EC 公開鍵 JWK を構築する。 */
export function toJwk(privateKey: Uint8Array, kid?: string): PublicKeyJwk {
  const pub = getP256PublicKey(privateKey, false);
  const jwk: Record<string, unknown> = {
    kty: 'EC',
    crv: 'P-256',
    x: b64u(pub.subarray(1, 33)),
    y: b64u(pub.subarray(33, 65)),
  };
  if (kid !== undefined) {
    jwk.kid = kid;
  }
  return jwk as PublicKeyJwk;
}

/** 固定テスト鍵（各エンティティで別鍵）。 */
export const LEAF_KEY = new Uint8Array(32).fill(11);
export const INTERMEDIATE_KEY = new Uint8Array(32).fill(13);
export const ANCHOR_KEY = new Uint8Array(32).fill(17);
export const WRONG_KEY = new Uint8Array(32).fill(23);

/** 固定テスト時刻（2026-01-01T00:00:00Z 近傍、エポック秒）。 */
export const NOW_SECONDS = 1_767_225_600;
/** `now` 依存注入用（ミリ秒）。 */
export const nowFn = (): number => NOW_SECONDS * 1000;

/**
 * 任意の payload を ES256 で署名した compact JWS を組み立てる。
 *
 * @param privateKey 署名鍵。
 * @param payload JWT payload。
 * @param header 追加ヘッダ（`kid` 等）。既定は `{ alg: 'ES256', typ: 'entity-statement+jwt' }`。
 */
export function signStatement(
  privateKey: Uint8Array,
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
): string {
  const fullHeader = { alg: 'ES256', typ: 'entity-statement+jwt', ...header };
  const headerSeg = Buffer.from(JSON.stringify(fullHeader)).toString('base64url');
  const payloadSeg = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const digest = sha256(new TextEncoder().encode(signingInput));
  const signature = signP256(digest, privateKey);
  return `${signingInput}.${b64u(signature)}`;
}

/** 標準的な有効期間クレーム（NOW を含む）。 */
export function validPeriod(): { iat: number; exp: number } {
  return { iat: NOW_SECONDS - 3600, exp: NOW_SECONDS + 3600 };
}

/**
 * 成功する 3 段チェーン（Leaf → Intermediate → Anchor）の URL → 応答マップを構築する。
 *
 * 返すマップの各値は本文（JWT）を持つ `Response` を返す。
 */
export interface FederationTopology {
  readonly leafId: string;
  readonly intermediateId: string;
  readonly anchorId: string;
  readonly responses: Map<string, string>;
}

/** JWT を返す成功レスポンスを生成する。 */
function jwtResponse(jwt: string): Response {
  return new Response(jwt, {
    status: 200,
    headers: { 'content-type': 'application/entity-statement+jwt' },
  });
}

/**
 * URL → JWT 文字列のマップから `fetch` モックを生成する。
 *
 * 未登録の URL は 404 を返す。`Response.url` は空文字（同一 origin 応答扱い）。
 */
export function makeFetchMock(responses: Map<string, string>): typeof fetch {
  return (async (input: string | URL | Request): Promise<Response> => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const jwt = responses.get(url);
    if (jwt === undefined) {
      return new Response('not found', { status: 404 });
    }
    return jwtResponse(jwt);
  }) as typeof fetch;
}

/**
 * 有効な 3 段トポロジ（Leaf → Intermediate → Anchor）を構築する。
 *
 * - Leaf EC: 自己署名、`authority_hints=[intermediate]`。
 * - Intermediate EC: 自己署名、`authority_hints=[anchor]`、`federation_fetch_endpoint` を持つ。
 * - Anchor EC: 自己署名、`federation_fetch_endpoint` を持つ。
 * - Intermediate → Leaf の Subordinate Statement（Intermediate 鍵で署名、Leaf の jwks を保証）。
 * - Anchor → Intermediate の Subordinate Statement（Anchor 鍵で署名、Intermediate の jwks を保証）。
 */
export function buildValidTopology(): FederationTopology {
  const leafId = 'https://leaf.example.eu';
  const intermediateId = 'https://intermediate.example.eu';
  const anchorId = 'https://anchor.example.eu';

  const leafJwks = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };
  const intermediateJwks = { keys: [toJwk(INTERMEDIATE_KEY, 'int-1')] };
  const anchorJwks = { keys: [toJwk(ANCHOR_KEY, 'anchor-1')] };

  const intFetch = `${intermediateId}/fetch`;
  const anchorFetch = `${anchorId}/fetch`;

  const leafEc = signStatement(
    LEAF_KEY,
    {
      iss: leafId,
      sub: leafId,
      ...validPeriod(),
      jwks: leafJwks,
      authority_hints: [intermediateId],
    },
    { kid: 'leaf-1' },
  );
  const intermediateEc = signStatement(
    INTERMEDIATE_KEY,
    {
      iss: intermediateId,
      sub: intermediateId,
      ...validPeriod(),
      jwks: intermediateJwks,
      authority_hints: [anchorId],
      metadata: { federation_entity: { federation_fetch_endpoint: intFetch } },
    },
    { kid: 'int-1' },
  );
  const anchorEc = signStatement(
    ANCHOR_KEY,
    {
      iss: anchorId,
      sub: anchorId,
      ...validPeriod(),
      jwks: anchorJwks,
      metadata: { federation_entity: { federation_fetch_endpoint: anchorFetch } },
    },
    { kid: 'anchor-1' },
  );

  // Subordinate Statements: parent が child の jwks を保証する。
  const intAboutLeaf = signStatement(INTERMEDIATE_KEY, {
    iss: intermediateId,
    sub: leafId,
    ...validPeriod(),
    jwks: leafJwks,
  });
  const anchorAboutInt = signStatement(ANCHOR_KEY, {
    iss: anchorId,
    sub: intermediateId,
    ...validPeriod(),
    jwks: intermediateJwks,
  });

  const responses = new Map<string, string>();
  responses.set(`${leafId}/.well-known/openid-federation`, leafEc);
  responses.set(`${intermediateId}/.well-known/openid-federation`, intermediateEc);
  responses.set(`${anchorId}/.well-known/openid-federation`, anchorEc);
  responses.set(`${intFetch}?sub=${encodeURIComponent(leafId)}`, intAboutLeaf);
  responses.set(`${anchorFetch}?sub=${encodeURIComponent(intermediateId)}`, anchorAboutInt);

  return { leafId, intermediateId, anchorId, responses };
}
