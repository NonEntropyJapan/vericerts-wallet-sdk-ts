/**
 * ファサード `receiveCredential` テスト用フィクスチャ。
 *
 * 実鍵素材のみを使い（モック署名器は使わない）、SD-JWT VC の digest / 署名と JWT Proof の署名は
 * 実際に計算される。ネットワークは**グローバル `fetch` を差し替えず** `fetchImpl` で注入し、
 * URL でルーティングして要求 URL / body / headers を記録する。これにより「そもそも fetch が
 * 発生しないこと」（非 HTTPS の入口拒否）を呼び出し記録から検証できる。
 */

import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import type { FetchLike } from '../../../../fetch-di.js';
import {
  buildSdJwtVc,
  HOLDER_DID,
  HOLDER_KEY_ID,
  HOLDER_PRIVATE_KEY,
  ISSUER,
} from '../../../eudi/issuance/__tests__/issuance-fixtures.js';
import type { ReceiveCredentialDeps } from '../types.js';

export { buildSdJwtVc, HOLDER_DID, HOLDER_KEY_ID, ISSUER };

/** 別立ての Authorization Server。 */
export const AS = 'https://as.example.eu';

export const ISSUER_METADATA_URL = `${ISSUER}/.well-known/openid-credential-issuer`;
export const AS_METADATA_URL = `${AS}/.well-known/oauth-authorization-server`;
export const ISSUER_AS_METADATA_URL = `${ISSUER}/.well-known/oauth-authorization-server`;
export const TOKEN_URL = `${ISSUER}/token`;
/**
 * AS Metadata 側の Token エンドポイント（Issuer Metadata の `TOKEN_URL` と**別 URL**）。
 *
 * `facade/receive.ts` は「Token / Credential は Issuer Metadata 側を正とする」と明文化している。
 * 既定のフィクスチャは両者を同じ URL にしているため、その判断が退行しても呼び出し記録に差が
 * 出ない。食い違いを作るテストは `asMetadataResponse({ token_endpoint: AS_TOKEN_URL })` を渡す。
 */
export const AS_TOKEN_URL = `${AS}/as-token`;
export const CREDENTIAL_URL = `${ISSUER}/credential`;
export const PAR_URL = `${AS}/par`;
export const AUTHZ_URL = `${AS}/authorize`;

export const CONFIGURATION_ID = 'urn:eudi:eaa:diploma:1';
export const ACCESS_TOKEN = 'access-token-value';
export const C_NONCE = 'c-nonce-value';
export const CLIENT_ID = 'wallet-client';
export const REDIRECT_URI = 'com.example.wallet://cb';

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
  callTo(url: string): FetchCall | undefined;
  formTo(url: string): URLSearchParams | undefined;
}

/** URL → Response のルーティングを持つスタブ fetch を作る。未登録 URL は 404 を返す。 */
export function createStubFetch(routes: Readonly<Record<string, () => Response>>): StubFetch {
  const calls: FetchCall[] = [];
  const fetchImpl: FetchLike = (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body });
    const route = Object.hasOwn(routes, url) ? routes[url] : undefined;
    return Promise.resolve(route === undefined ? new Response('', { status: 404 }) : route());
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

/** JSON レスポンスを作る。 */
export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Credential Offer URI（値渡し）を組み立てる。 */
export function buildOfferURI(offer: Readonly<Record<string, unknown>>): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

/** `pre-authorized_code` grant の Offer URI。 */
export function preAuthorizedOfferURI(): string {
  return buildOfferURI({
    credential_issuer: ISSUER,
    credential_configuration_ids: [CONFIGURATION_ID],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'pre-auth-code-123',
      },
    },
  });
}

/** `authorization_code` grant の Offer URI。 */
export function authorizationCodeOfferURI(grant: Readonly<Record<string, unknown>> = {}): string {
  return buildOfferURI({
    credential_issuer: ISSUER,
    credential_configuration_ids: [CONFIGURATION_ID],
    grants: { authorization_code: grant },
  });
}

/** Issuer Metadata 応答。`authorization_servers` は任意で載せる。 */
export function issuerMetadataResponse(extra: Readonly<Record<string, unknown>> = {}): Response {
  return json({
    credential_issuer: ISSUER,
    credential_endpoint: CREDENTIAL_URL,
    token_endpoint: TOKEN_URL,
    ...extra,
  });
}

/** AS Metadata 応答（RFC 8414 + RFC 9126）。 */
export function asMetadataResponse(overrides: Readonly<Record<string, unknown>> = {}): Response {
  return json({
    issuer: AS,
    pushed_authorization_request_endpoint: PAR_URL,
    authorization_endpoint: AUTHZ_URL,
    token_endpoint: TOKEN_URL,
    ...overrides,
  });
}

export const parResponse = (): Response =>
  json({ request_uri: 'urn:ietf:params:oauth:request_uri:abc', expires_in: 60 }, 201);

export const tokenResponse =
  (tokenType = 'Bearer'): (() => Response) =>
  () =>
    json({
      access_token: ACCESS_TOKEN,
      token_type: tokenType,
      expires_in: 3600,
      c_nonce: C_NONCE,
      c_nonce_expires_in: 300,
    });

export const credentialResponse = (): Response =>
  json({ credential: buildSdJwtVc({ vct: CONFIGURATION_ID, claims: { degree: 'Laurea' } }) });

export const deferredResponse = (): Response => json({ transaction_id: 'tx-42' });

/** 既定の依存。`authorize` は PAR で push された `state` をそのまま返す。 */
export function facadeDeps(
  stub: StubFetch,
  overrides: Partial<ReceiveCredentialDeps> = {},
): ReceiveCredentialDeps {
  return {
    signer: createPrivateKeySigner(HOLDER_PRIVATE_KEY, 'ES256'),
    holderDid: HOLDER_DID,
    keyId: HOLDER_KEY_ID,
    format: CONFIGURATION_ID,
    fetchImpl: stub.fetchImpl,
    ...overrides,
  };
}

/** `authorization_code` 経路で使う依存（認可 UI・client 登録情報つき）。 */
export function authorizationCodeDeps(
  stub: StubFetch,
  overrides: Partial<ReceiveCredentialDeps> = {},
): ReceiveCredentialDeps {
  return facadeDeps(stub, {
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    authorize: (url) => {
      void url;
      const state = stub.formTo(PAR_URL)?.get('state') ?? '';
      return Promise.resolve({ code: 'authz-code-value', state, iss: AS });
    },
    ...overrides,
  });
}
