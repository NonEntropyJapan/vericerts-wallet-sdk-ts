/**
 * eudi/issuance テスト用フィクスチャ。
 *
 * 実鍵素材のみを使う（モック署名器は使わない）。P-256 秘密鍵から `CredentialSigner` を作り、
 * SD-JWT VC は Disclosure・digest・署名まで実際に計算して組み立てる。
 *
 * **PID の SD-JWT は `createSdJwt` では作れない。** `createSdJwt` は発行経路の GDPR Art.9 ガード
 * （`sdjwt/gdpr-guard.ts`）を通り、`family_name` / `given_name` / `birth_date` を含む発行を
 * `10607` で拒否するためである（SDK は PID を発行しない）。受領側の
 * テストが必要とするのは「加盟国指定の PID Provider が発行した PID を Wallet が受け取る」状況
 * なので、ここでは Issuer 側の組み立てを最小限に再現する。digest・salt・署名はいずれも本物で、
 * `parseSdJwt` / `recoverClaims` が実際に検証する経路をそのまま通る。
 *
 * ネットワークは**グローバル `fetch` を差し替えず** `fetchImpl` で注入する。URL でルーティングし、
 * 要求された URL と body を記録するので、「非 HTTPS のエンドポイントは fetch を発生させずに
 * 拒否される」ことも呼び出し記録の空を見て確認できる。
 */

import { base64urlnopad } from '@scure/base';
import { encodeDisclosure } from '../../../../credential/sdjwt/disclosure.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { PID_VCT } from '../../../../eudi/pid/index.js';
import type { FetchLike } from '../../../../fetch-di.js';
import type { ReceiveDeps } from '../types.js';

/** Issuer（PID Provider 相当）の決定論的な P-256 秘密鍵。 */
export const ISSUER_PRIVATE_KEY = new Uint8Array(32).fill(7);

/** Holder（Wallet）の決定論的な P-256 秘密鍵。 */
export const HOLDER_PRIVATE_KEY = new Uint8Array(32).fill(9);

/** Credential Offer の `credential_issuer`。 */
export const ISSUER = 'https://issuer.example.eu';

/** Issuer Metadata の well-known URL。 */
export const METADATA_URL = `${ISSUER}/.well-known/openid-credential-issuer`;
export const AS_METADATA_URL = `${ISSUER}/.well-known/oauth-authorization-server`;

/** Issuer Metadata が宣言する Token Endpoint。 */
export const TOKEN_URL = `${ISSUER}/token`;

/** Issuer Metadata が宣言する Credential Endpoint。 */
export const CREDENTIAL_URL = `${ISSUER}/credential`;

/** Issuer Metadata が宣言する Nonce Endpoint（WUA 添付時のみ使う）。 */
export const NONCE_URL = `${ISSUER}/nonce`;

/** Nonce Endpoint が払い出す c_nonce。WUA-PoP の `nonce` に載る想定値。 */
export const AS_C_NONCE = 'as-issued-c-nonce-123';

/** (Q)EAA の VC Type URI（Catalogue 登録済みを想定）。 */
export const EAA_VCT = 'urn:eudi:eaa:diploma:1';

/** Holder の検証鍵 ID（`did#fragment`）。 */
export const HOLDER_KEY_ID = 'did:key:zHolder#key-1';

/** Holder DID（JWT Proof の `iss`）。 */
export const HOLDER_DID = 'did:key:zHolder';

/** ARF PID Rulebook の必須属性をすべて満たす PID クレーム。 */
export const VALID_PID_CLAIMS: Readonly<Record<string, unknown>> = {
  family_name: 'Bianchi',
  given_name: 'Mario',
  birth_date: '1980-05-17',
  issuance_date: '2026-01-10',
  expiry_date: '2031-01-10',
  issuing_authority: 'Ministero dell Interno',
  issuing_country: 'IT',
};

/** UTF-8 文字列を base64url（パディングなし）エンコードする。 */
function b64url(text: string): string {
  return base64urlnopad.encode(new TextEncoder().encode(text));
}

/** `buildSdJwtVc` の入力。 */
export interface BuildSdJwtVcOptions {
  /** VC Type URI（`vct` クレーム）。省略時は PID。 */
  readonly vct?: string;
  /** 発行者識別子（`iss` クレーム）。省略時は {@link ISSUER}。 */
  readonly iss?: string;
  /** 選択的開示するクレーム（すべて Disclosure へ回す）。 */
  readonly claims: Readonly<Record<string, unknown>>;
}

/**
 * Issuer 署名済みの SD-JWT VC を組み立てる（全クレームを選択的開示にする）。
 *
 * salt は決定論的に採番し（テストの再現性のため）、digest・署名は実際に計算する。
 *
 * @param options vct と開示クレーム。
 * @returns SD-JWT VC のコンパクト表現（`<issuerJwt>~<d1>~...~`）。
 */
export function buildSdJwtVc(options: BuildSdJwtVcOptions): string {
  const signer = createPrivateKeySigner(ISSUER_PRIVATE_KEY, 'ES256');
  const disclosures = Object.entries(options.claims).map(([name, value], index) =>
    encodeDisclosure(name, value, `salt-${index}`),
  );
  const payload = {
    iss: options.iss ?? ISSUER,
    vct: options.vct ?? PID_VCT,
    iat: 1_767_000_000,
    _sd_alg: 'sha-256',
    _sd: disclosures.map((disclosure) => disclosure.digest),
  };
  const header = { alg: 'ES256', typ: 'dc+sd-jwt' };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = signer.sign(new TextEncoder().encode(signingInput));
  const issuerJwt = `${signingInput}.${base64urlnopad.encode(signature)}`;
  return `${issuerJwt}~${disclosures.map((disclosure) => disclosure.encoded).join('~')}~`;
}

/** Credential Offer URI（値渡し）を組み立てる。 */
export function buildOfferURI(offer: Readonly<Record<string, unknown>>): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

/** pre-authorized_code grant を持つ既定の Offer URI。 */
export function defaultOfferURI(configurationId: string = PID_VCT): string {
  return buildOfferURI({
    credential_issuer: ISSUER,
    credential_configuration_ids: [configurationId],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'pre-auth-code-123',
      },
    },
  });
}

/** 1 回の HTTP 呼び出しの記録。 */
export interface FetchCall {
  /** 要求された URL。 */
  readonly url: string;
  /** 送信された body。 */
  readonly body: string;
}

/** URL でルーティングするスタブ fetch と、その呼び出し記録。 */
export interface StubFetch {
  /** `fetchImpl` として注入する実装。 */
  readonly fetchImpl: FetchLike;
  /** 要求された URL / body の記録（呼ばれた順）。 */
  readonly calls: FetchCall[];
}

/**
 * URL → レスポンス生成関数のルーティング表からスタブ fetch を作る。
 *
 * ルートに無い URL は 404 を返す（例外にしない）。「そもそも fetch が発生しないこと」を
 * 検証したいテストは `calls` の長さで判定する。
 */
export function createStubFetch(routes: Readonly<Record<string, () => Response>>): StubFetch {
  const calls: FetchCall[] = [];
  const fetchImpl: FetchLike = (url, init) => {
    calls.push({ url, body: init.body });
    const route = Object.hasOwn(routes, url) ? routes[url] : undefined;
    return Promise.resolve(route === undefined ? new Response('', { status: 404 }) : route());
  };
  return { fetchImpl, calls };
}

/** JSON 本文の 200 応答を返す。 */
export function jsonResponse(body: Readonly<Record<string, unknown>>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** 既定の Issuer Metadata 応答（`nonce_endpoint` を告知しない = WUA 添付は fail-closed）。 */
export function metadataResponse(): Response {
  return jsonResponse({
    credential_issuer: ISSUER,
    credential_endpoint: CREDENTIAL_URL,
    token_endpoint: TOKEN_URL,
  });
}

/** `nonce_endpoint` も告知する Issuer Metadata 応答（WUA 添付が成立する構成）。 */
export function metadataWithNonceResponse(): Response {
  return jsonResponse({
    credential_issuer: ISSUER,
    credential_endpoint: CREDENTIAL_URL,
    token_endpoint: TOKEN_URL,
    nonce_endpoint: NONCE_URL,
  });
}

/** Nonce Endpoint の既定応答。 */
export function nonceResponse(): Response {
  return jsonResponse({ c_nonce: AS_C_NONCE });
}

/** 既定の Token 応答（access_token と c_nonce）。 */
export function tokenResponse(): Response {
  return jsonResponse({
    access_token: 'access-token-abc',
    token_type: 'Bearer',
    expires_in: 300,
    c_nonce: 'c-nonce-xyz',
    c_nonce_expires_in: 300,
  });
}

/** 受領する SD-JWT VC を返す Credential 応答。 */
export function credentialResponse(sdJwt: string): Response {
  return jsonResponse({ credential: sdJwt });
}

/**
 * AS Metadata（RFC 8414）応答。Token Endpoint は AS Metadata から引く（OID4VCI 1.0 §6）。
 * `authorization_servers` を告知しない Issuer は自身が AS なので、Issuer 直下に置く。
 */
export function asMetadataResponse(tokenEndpoint = TOKEN_URL): Response {
  return jsonResponse({ issuer: ISSUER, token_endpoint: tokenEndpoint });
}

/** 既定の 3 エンドポイントを備えたスタブ fetch を作る（`nonce_endpoint` は告知しない）。 */
export function createIssuerStub(sdJwt: string): StubFetch {
  return createStubFetch({
    [METADATA_URL]: metadataResponse,
    [AS_METADATA_URL]: () => asMetadataResponse(),
    [TOKEN_URL]: tokenResponse,
    [CREDENTIAL_URL]: () => credentialResponse(sdJwt),
  });
}

/** Nonce Endpoint まで備えたスタブ fetch を作る（WUA 添付の経路で使う）。 */
export function createIssuerStubWithNonce(sdJwt: string): StubFetch {
  return createStubFetch({
    [METADATA_URL]: metadataWithNonceResponse,
    [AS_METADATA_URL]: () => asMetadataResponse(),
    [NONCE_URL]: nonceResponse,
    [TOKEN_URL]: tokenResponse,
    [CREDENTIAL_URL]: () => credentialResponse(sdJwt),
  });
}

/** Holder 署名鍵（ES256、実鍵）。 */
export function holderSigner(): CredentialSigner {
  return createPrivateKeySigner(HOLDER_PRIVATE_KEY, 'ES256');
}

/** 受領フローの既定の依存。`fetchImpl` はテストごとに注入する。 */
export function receiveDeps(fetchImpl: FetchLike): ReceiveDeps {
  return { signer: holderSigner(), holderDid: HOLDER_DID, keyId: HOLDER_KEY_ID, fetchImpl };
}
