/**
 * Authorization Code Flow（PAR + PKCE）テスト用フィクスチャ。
 *
 * PAR と PKCE を使う Authorization Code Flow の統合テストが
 * 使う。実鍵素材のみを使い（モック署名器は使わない）、JWT Proof の署名は実際に計算される。
 *
 * ネットワークは**グローバル `fetch` を差し替えず** `fetchImpl` で注入する。URL でルーティングし
 * 要求 URL / body / headers を記録するので、「非 HTTPS のエンドポイントは fetch を発生させずに
 * 拒否される」「`state` 不一致では Token Request が 1 度も飛ばない」ことを呼び出し記録から
 * 確認できる（`eudi/issuance/__tests__/issuance-fixtures.ts` と同じ方針）。
 */

import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import type { FetchLike } from '../../../../fetch-di.js';
import type { AuthorizationCodeFlowDeps, AuthorizationCodeFlowOptions } from '../types.js';

/** Holder（Wallet）の決定論的な P-256 秘密鍵。 */
export const HOLDER_PRIVATE_KEY = new Uint8Array(32).fill(9);

export const AS = 'https://as.example.com';
export const ISSUER = 'https://issuer.example.com';
export const PAR_URL = `${AS}/par`;
export const AUTHZ_URL = `${AS}/authorize`;
export const TOKEN_URL = `${AS}/token`;
export const CREDENTIAL_URL = `${ISSUER}/credential`;

export const CLIENT_ID = 'wallet-client';
export const REDIRECT_URI = 'com.example.wallet://cb';
export const HOLDER_DID = 'did:key:z6MkholderTest';
export const HOLDER_KEY_ID = `${HOLDER_DID}#key-1`;

/** AS が払い出す request_uri（RFC 9126）。 */
export const PAR_REQUEST_URI = 'urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c';

export const ACCESS_TOKEN = 'access-token-value';
export const C_NONCE = 'c-nonce-value';
export const CREDENTIAL = 'eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ0ZXN0In0.sig';

/** 1 回の HTTP 呼び出しの記録。 */
export interface FetchCall {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: string;
}

/** URL でルーティングするスタブ fetch と、その呼び出し記録。 */
export interface StubFetch {
  readonly fetchImpl: FetchLike;
  readonly calls: FetchCall[];
  /** 指定 URL への最初の呼び出し（無ければ `undefined`）。 */
  callTo(url: string): FetchCall | undefined;
  /** 指定 URL へ送った body を `URLSearchParams` として読む。 */
  formTo(url: string): URLSearchParams | undefined;
}

type Routes = Record<string, () => Response>;

/** URL → Response のルーティングを持つスタブ fetch を作る。未登録 URL は 404 を返す。 */
export function createStubFetch(routes: Routes): StubFetch {
  const calls: FetchCall[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body });
    const route = Object.hasOwn(routes, url) ? routes[url] : undefined;
    return route === undefined ? new Response('not found', { status: 404 }) : route();
  };
  return {
    fetchImpl,
    calls,
    callTo: (url) => calls.find((c) => c.url === url),
    formTo(url) {
      const call = calls.find((c) => c.url === url);
      return call === undefined ? undefined : new URLSearchParams(call.body);
    },
  };
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export const parResponse = (): Response =>
  json({ request_uri: PAR_REQUEST_URI, expires_in: 60 }, 201);

export const tokenResponse = (): Response =>
  json(
    {
      access_token: ACCESS_TOKEN,
      token_type: 'Bearer',
      expires_in: 3600,
      c_nonce: C_NONCE,
      c_nonce_expires_in: 300,
    },
    200,
  );

/** DPoP 束縛 access_token を返す Token 応答（RFC 9449 §5）。 */
export const dpopTokenResponse = (): Response =>
  json(
    {
      access_token: ACCESS_TOKEN,
      token_type: 'DPoP',
      expires_in: 3600,
      c_nonce: C_NONCE,
      c_nonce_expires_in: 300,
    },
    200,
  );

export const credentialResponse = (): Response =>
  json({ credential: CREDENTIAL, c_nonce: 'next-nonce' }, 200);

export const deferredResponse = (): Response => json({ transaction_id: 'tx-42' }, 200);

/** PAR / Token / Credential の 3 経路が成功するスタブ。 */
export function createHappyStub(): StubFetch {
  return createStubFetch({
    [PAR_URL]: parResponse,
    [TOKEN_URL]: tokenResponse,
    [CREDENTIAL_URL]: credentialResponse,
  });
}

/** 既定の要求内容。個別のテストで上書きする。 */
export function flowOptions(
  overrides: Partial<AuthorizationCodeFlowOptions> = {},
): AuthorizationCodeFlowOptions {
  return {
    endpoints: {
      parEndpoint: PAR_URL,
      authorizationEndpoint: AUTHZ_URL,
      tokenEndpoint: TOKEN_URL,
      credentialEndpoint: CREDENTIAL_URL,
    },
    credentialIssuer: ISSUER,
    authorizationServerIssuer: AS,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    format: 'dc+sd-jwt',
    credentialDefinition: { type: ['UniversityDegree'] },
    ...overrides,
  };
}

/**
 * 既定の依存。`authorize` は認可 URL を記録し、PAR で push された `state` をそのまま返す
 * （正常系の AS の振る舞い）。
 */
export function flowDeps(
  stub: StubFetch,
  overrides: Partial<AuthorizationCodeFlowDeps> = {},
): AuthorizationCodeFlowDeps & { readonly authorizationUrls: string[] } {
  const authorizationUrls: string[] = [];
  return {
    signer: createPrivateKeySigner(HOLDER_PRIVATE_KEY, 'ES256'),
    holderDid: HOLDER_DID,
    keyId: HOLDER_KEY_ID,
    fetchImpl: stub.fetchImpl,
    authorize: async (url) => {
      authorizationUrls.push(url);
      const state = stub.formTo(PAR_URL)?.get('state') ?? '';
      return { code: 'authz-code-value', state, iss: AS };
    },
    authorizationUrls,
    ...overrides,
  };
}
