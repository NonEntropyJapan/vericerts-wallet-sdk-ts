/**
 * pre-authorized_code 経路の AS 選択・Metadata 照合・旧 Draft フォールバックの条件
 * （OID4VCI 1.0 §4.1.1 / RFC 8414 §3.3）。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { parseCredentialOffer } from '../../offer/oid4vci-offer.js';
import { receiveCredential } from '../receive.js';
import {
  AS,
  AS_METADATA_URL,
  AS_TOKEN_URL,
  buildOfferURI,
  CONFIGURATION_ID,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  facadeDeps,
  ISSUER,
  ISSUER_AS_METADATA_URL,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  json,
  TOKEN_URL,
  tokenResponse,
} from './facade-fixtures.js';

const OTHER_AS = 'https://other.example.eu';
const OTHER_AS_METADATA_URL = `${OTHER_AS}/.well-known/oauth-authorization-server`;
const OTHER_AS_TOKEN_URL = `${OTHER_AS}/token`;
const EVIL_AS = 'https://evil.example';
const EVIL_AS_METADATA_URL = `${EVIL_AS}/.well-known/oauth-authorization-server`;
const GRANT_KEY = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

/** pre-authorized_code grant（任意で `authorization_server`）の Offer URI。 */
function preAuthOffer(authorizationServer?: string): string {
  return buildOfferURI({
    credential_issuer: ISSUER,
    credential_configuration_ids: [CONFIGURATION_ID],
    grants: {
      [GRANT_KEY]: {
        'pre-authorized_code': 'pre-auth-code-123',
        ...(authorizationServer === undefined ? {} : { authorization_server: authorizationServer }),
      },
    },
  });
}

/** Issuer 告知（`authorization_servers`）と AS ごとの Metadata を張ったスタブ。 */
function multiAsStub(
  asMetadataOverrides: Readonly<Record<string, () => Response>> = {},
): ReturnType<typeof createStubFetch> {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () =>
      issuerMetadataResponse({
        token_endpoint: undefined,
        authorization_servers: [OTHER_AS, AS],
      }),
    [OTHER_AS_METADATA_URL]: () => json({ issuer: OTHER_AS, token_endpoint: OTHER_AS_TOKEN_URL }),
    [AS_METADATA_URL]: () => json({ issuer: AS, token_endpoint: AS_TOKEN_URL }),
    [OTHER_AS_TOKEN_URL]: tokenResponse(),
    [AS_TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: credentialResponse,
    ...asMetadataOverrides,
  });
}

describe('pre-authorized_code grant の authorization_server', () => {
  test('grant を発行した AS（告知の先頭ではない）の token_endpoint へ送る', async () => {
    const stub = multiAsStub();
    await receiveCredential(preAuthOffer(AS), facadeDeps(stub));
    expect(stub.callTo(AS_TOKEN_URL)).toBeDefined();
    // 先頭の AS へは Metadata 取得も Token Request も飛ばない（コードを誤った AS へ送らない）。
    expect(stub.callTo(OTHER_AS_METADATA_URL)).toBeUndefined();
    expect(stub.callTo(OTHER_AS_TOKEN_URL)).toBeUndefined();
  });

  test('宣言が無ければ従来どおり authorization_servers の先頭', async () => {
    const stub = multiAsStub();
    await receiveCredential(preAuthOffer(), facadeDeps(stub));
    expect(stub.callTo(OTHER_AS_TOKEN_URL)).toBeDefined();
    expect(stub.callTo(AS_TOKEN_URL)).toBeUndefined();
  });

  test('末尾スラッシュだけが違う宣言は同一 AS として受理し、宣言値で Metadata を引く', async () => {
    const stub = multiAsStub();
    await receiveCredential(preAuthOffer(`${AS}/`), facadeDeps(stub));
    expect(stub.callTo(AS_TOKEN_URL)).toBeDefined();
  });

  test('告知に無い authorization_server は 8010 で落ち、Metadata も Token Request も飛ばない', async () => {
    const stub = multiAsStub({
      [EVIL_AS_METADATA_URL]: () => json({ issuer: EVIL_AS, token_endpoint: `${EVIL_AS}/token` }),
    });
    await expect(receiveCredential(preAuthOffer(EVIL_AS), facadeDeps(stub))).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_REQUEST_FAILED,
      context: { reason: 'authorization_server_not_declared' },
    });
    expect(stub.callTo(EVIL_AS_METADATA_URL)).toBeUndefined();
    expect(stub.calls.some((c) => c.url.startsWith(EVIL_AS))).toBe(false);
  });

  test('authorization_servers を告知しない Issuer への宣言は照合できないので fail-closed', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [ISSUER_AS_METADATA_URL]: () => json({ issuer: ISSUER, token_endpoint: TOKEN_URL }),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    await expect(receiveCredential(preAuthOffer(AS), facadeDeps(stub))).rejects.toMatchObject({
      context: { reason: 'authorization_server_not_declared' },
    });
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
  });

  test('空文字・非文字列の authorization_server を持つ grant は Offer のパースで 3003', async () => {
    for (const bad of ['', 42, null]) {
      const uri = buildOfferURI({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIGURATION_ID],
        grants: { [GRANT_KEY]: { 'pre-authorized_code': 'c', authorization_server: bad } },
      });
      await expect(parseCredentialOffer(uri)).rejects.toMatchObject({
        code: ErrorCodes.OFFER_URI_PARSE_FAILED,
      });
    }
  });
});

describe('Metadata の識別子照合（RFC 8414 §3.3 / OID4VCI 1.0 §12.2.4）', () => {
  test('AS Metadata の issuer が取得に用いた AS 識別子と異なれば 3004（issuer_mismatch）で Token Request は飛ばない', async () => {
    const stub = multiAsStub({
      // 同一 origin の別テナントの文書（別の token_endpoint）を返す AS。
      [AS_METADATA_URL]: () => json({ issuer: `${AS}/tenant-b`, token_endpoint: AS_TOKEN_URL }),
    });
    await expect(receiveCredential(preAuthOffer(AS), facadeDeps(stub))).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      context: { reason: 'issuer_mismatch' },
    });
    expect(stub.callTo(AS_TOKEN_URL)).toBeUndefined();
  });

  test('AS Metadata に issuer が無い・非文字列でも issuer_mismatch', async () => {
    for (const body of [
      { token_endpoint: AS_TOKEN_URL },
      { issuer: 7, token_endpoint: AS_TOKEN_URL },
    ]) {
      const stub = multiAsStub({ [AS_METADATA_URL]: () => json(body) });
      await expect(receiveCredential(preAuthOffer(AS), facadeDeps(stub))).rejects.toMatchObject({
        context: { reason: 'issuer_mismatch' },
      });
    }
  });

  test('末尾スラッシュだけ違う issuer は一致とみなす', async () => {
    const stub = multiAsStub({
      [AS_METADATA_URL]: () => json({ issuer: `${AS}/`, token_endpoint: AS_TOKEN_URL }),
    });
    await receiveCredential(preAuthOffer(AS), facadeDeps(stub));
    expect(stub.callTo(AS_TOKEN_URL)).toBeDefined();
  });

  test('Issuer Metadata の credential_issuer が Offer の値と異なれば 3004（issuer_mismatch）', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () =>
        issuerMetadataResponse({ credential_issuer: 'https://tenant-b.example.eu' }),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    await expect(receiveCredential(preAuthOffer(), facadeDeps(stub))).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      context: { reason: 'issuer_mismatch' },
    });
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
  });

  test('Issuer Metadata に credential_issuer が無ければ issuer_mismatch', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () =>
        json({ credential_endpoint: CREDENTIAL_URL, token_endpoint: TOKEN_URL }),
    });
    await expect(receiveCredential(preAuthOffer(), facadeDeps(stub))).rejects.toMatchObject({
      context: { reason: 'issuer_mismatch' },
    });
  });
});

describe('旧 Draft token_endpoint へのフォールバック条件', () => {
  /** Issuer が旧 `token_endpoint`（TOKEN_URL）を宣言し、AS Metadata の応答だけを差し替えるスタブ。 */
  function legacyStub(asMetadata: () => Response): ReturnType<typeof createStubFetch> {
    return createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [ISSUER_AS_METADATA_URL]: asMetadata,
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
  }

  test('AS Metadata が 404（到達不能系）なら旧 token_endpoint へ落ちる', async () => {
    const stub = legacyStub(() => new Response('', { status: 404 }));
    await receiveCredential(preAuthOffer(), facadeDeps(stub));
    expect(stub.callTo(TOKEN_URL)).toBeDefined();
  });

  test('AS Metadata が通信失敗（fetch_failed）でも旧 token_endpoint へ落ちる', async () => {
    const stub = legacyStub(() => {
      throw new TypeError('network down');
    });
    await receiveCredential(preAuthOffer(), facadeDeps(stub));
    expect(stub.callTo(TOKEN_URL)).toBeDefined();
  });

  test.each([
    ['issuer_mismatch', () => json({ issuer: 'https://other.example', token_endpoint: TOKEN_URL })],
    [
      'non_https_endpoint',
      () => json({ issuer: ISSUER, token_endpoint: 'http://issuer.example.eu/token' }),
    ],
    ['missing_endpoint', () => json({ issuer: ISSUER })],
    [
      'invalid_content_type',
      () => new Response('{}', { status: 200, headers: { 'Content-Type': 'text/html' } }),
    ],
    ['invalid_metadata', () => json([])],
  ] as const)('AS Metadata が検査で拒否された（%s）なら旧 token_endpoint へは落ちず Token Request は飛ばない', async (reason, asMetadata) => {
    const stub = legacyStub(asMetadata);
    await expect(receiveCredential(preAuthOffer(), facadeDeps(stub))).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      context: { reason },
    });
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
  });

  /** ブラウザ service worker の `redirect: 'manual'` 応答（`Location` 不可視）。 */
  function opaqueRedirect(): Response {
    const response = new Response(null, { status: 200 });
    Object.defineProperty(response, 'type', { value: 'opaqueredirect' });
    return response;
  }

  // リダイレクト検査（非公開ホップ・opaqueredirect・Location 欠落）による拒否はネットワーク不達では
  // ない。`fetch_failed` に潰れると到達不能時だけ許す旧 token_endpoint への迂回路になる。
  test.each([
    [
      '非公開ホストへの 302',
      () => new Response(null, { status: 302, headers: { location: 'https://10.0.0.5/steal' } }),
    ],
    ['opaqueredirect', opaqueRedirect],
    ['Location 欠落の 302', () => new Response(null, { status: 302 })],
  ] as const)('AS Metadata 取得のリダイレクト検査拒否（%s）は redirect_rejected で、旧 token_endpoint へは落ちず Token Request は飛ばない', async (_label, asMetadata) => {
    const stub = legacyStub(asMetadata);
    await expect(receiveCredential(preAuthOffer(), facadeDeps(stub))).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      context: { reason: 'redirect_rejected' },
    });
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
    // 非公開ホップへは GET も飛ばない。
    expect(stub.callTo('https://10.0.0.5/steal')).toBeUndefined();
  });
});
