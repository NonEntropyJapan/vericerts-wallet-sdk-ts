/**
 * AS Metadata 取得の入口検査（RFC 8414）。
 *
 * 検査は Issuer Metadata 取得（`eudi/issuance/metadata.ts`）と**同一**でなければならない
 * （`internal/auth/well-known-json/index.ts` を共有する）。本テストはその同一性を AS 側でも
 * 実挙動として固定する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { fetchIssuerMetadata } from '../../../eudi/issuance/metadata.js';
import { fetchAuthorizationServerMetadata } from '../../oid4vci-as-metadata.js';
import {
  AS,
  AS_METADATA_URL,
  AUTHZ_URL,
  asMetadataResponse,
  createStubFetch,
  ISSUER,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  json,
  PAR_URL,
  TOKEN_URL,
} from './facade-fixtures.js';

describe('fetchAuthorizationServerMetadata の正常系', () => {
  test('PAR / Authorization / Token の 3 エンドポイントを解決する', async () => {
    const stub = createStubFetch({ [AS_METADATA_URL]: () => asMetadataResponse() });
    const endpoints = await fetchAuthorizationServerMetadata(AS, stub.fetchImpl);
    expect(endpoints).toEqual({
      issuer: AS,
      parEndpoint: PAR_URL,
      authorizationEndpoint: AUTHZ_URL,
      tokenEndpoint: TOKEN_URL,
    });
    expect(stub.callTo(AS_METADATA_URL)?.method).toBe('GET');
  });

  test('末尾スラッシュのある識別子でも well-known URL が二重スラッシュにならない', async () => {
    const stub = createStubFetch({ [AS_METADATA_URL]: () => asMetadataResponse() });
    await fetchAuthorizationServerMetadata(`${AS}/`, stub.fetchImpl);
    expect(stub.callTo(AS_METADATA_URL)).toBeDefined();
  });

  // RFC 8414 §3.1: path 成分を持つ識別子は host と path の「あいだ」へ well-known を挿入する。
  test.each([
    [
      'https://idp.example.com/realms/acme',
      'https://idp.example.com/.well-known/oauth-authorization-server/realms/acme',
    ],
    [
      'https://idp.example.com/realms/acme/',
      'https://idp.example.com/.well-known/oauth-authorization-server/realms/acme',
    ],
    ['https://idp.example.com', 'https://idp.example.com/.well-known/oauth-authorization-server'],
    ['https://idp.example.com/', 'https://idp.example.com/.well-known/oauth-authorization-server'],
  ])('識別子 %s の AS Metadata は %s から取る', async (issuer, expectedUrl) => {
    const stub = createStubFetch({ [expectedUrl]: () => asMetadataResponse({ issuer }) });
    const endpoints = await fetchAuthorizationServerMetadata(issuer, stub.fetchImpl);
    expect(endpoints.tokenEndpoint).toBe(TOKEN_URL);
    expect(stub.calls.map((c) => c.url)).toEqual([expectedUrl]);
  });

  test('path 付き識別子でも Issuer Metadata（OID4VCI §11.2.2）は追記形のまま', async () => {
    const issuer = 'https://issuer.example.com/tenant/a';
    const appended = `${issuer}/.well-known/openid-credential-issuer`;
    const stub = createStubFetch({
      [appended]: () => issuerMetadataResponse({ credential_issuer: issuer }),
    });
    await fetchIssuerMetadata(issuer, stub.fetchImpl);
    expect(stub.calls.map((c) => c.url)).toEqual([appended]);
  });
});

describe('fetchAuthorizationServerMetadata の入口検査（fetchIssuerMetadata と同一）', () => {
  test('非 HTTPS の識別子は fetch を 1 度も発生させずに拒否する', async () => {
    const stub = createStubFetch({});
    await expect(
      fetchAuthorizationServerMetadata('http://as.example.eu', stub.fetchImpl),
    ).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      context: { reason: 'non_https_issuer' },
    });
    expect(stub.calls).toHaveLength(0);
  });

  test('リダイレクトで HTTP へ降格した応答は拒否する', async () => {
    // 構築した `Response` の `url` は空文字なので、最終 URL を明示して降格を再現する
    // （`jar/__tests__/fetch-jar.test.ts` と同じ手法）。
    const downgraded = asMetadataResponse();
    Object.defineProperty(downgraded, 'url', {
      value: 'http://as.example.eu/.well-known/oauth-authorization-server',
    });
    await expect(
      fetchAuthorizationServerMetadata(AS, () => Promise.resolve(downgraded)),
    ).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      context: { reason: 'insecure_redirect' },
    });
  });

  test('非 2xx は http_error として拒否する', async () => {
    const stub = createStubFetch({ [AS_METADATA_URL]: () => json({}, 500) });
    await expect(fetchAuthorizationServerMetadata(AS, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'http_error' },
    });
  });

  test('JSON でない本文は invalid_json として拒否する', async () => {
    const stub = createStubFetch({
      [AS_METADATA_URL]: () =>
        new Response('not json', {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    });
    await expect(fetchAuthorizationServerMetadata(AS, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'invalid_json' },
    });
  });

  test('配列の本文は invalid_metadata として拒否する', async () => {
    const stub = createStubFetch({ [AS_METADATA_URL]: () => json([]) });
    await expect(fetchAuthorizationServerMetadata(AS, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'invalid_metadata' },
    });
  });

  test('fetch の失敗は fetch_failed へ正規化する（URL を漏らさない）', async () => {
    await expect(
      fetchAuthorizationServerMetadata(AS, () => Promise.reject(new Error('boom'))),
    ).rejects.toMatchObject({ context: { reason: 'fetch_failed' } });
  });
});

describe('fetchAuthorizationServerMetadata が発見したエンドポイントへの HTTPS 必須', () => {
  test('PAR エンドポイントの告知が無ければ fail-closed', async () => {
    const stub = createStubFetch({
      [AS_METADATA_URL]: () =>
        json({ issuer: AS, authorization_endpoint: AUTHZ_URL, token_endpoint: TOKEN_URL }),
    });
    await expect(fetchAuthorizationServerMetadata(AS, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'missing_endpoint' },
    });
  });

  test('authorization_endpoint の欠落も fail-closed', async () => {
    const stub = createStubFetch({
      [AS_METADATA_URL]: () =>
        json({
          issuer: AS,
          pushed_authorization_request_endpoint: PAR_URL,
          token_endpoint: TOKEN_URL,
        }),
    });
    await expect(fetchAuthorizationServerMetadata(AS, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'missing_endpoint' },
    });
  });

  test('発見したエンドポイントが非 HTTPS なら拒否する', async () => {
    const stub = createStubFetch({
      [AS_METADATA_URL]: () =>
        asMetadataResponse({ pushed_authorization_request_endpoint: 'http://as.example.eu/par' }),
    });
    await expect(fetchAuthorizationServerMetadata(AS, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'non_https_endpoint' },
    });
  });

  test('継承した pushed_authorization_request_endpoint は採用しない（own 限定読み）', async () => {
    const key = 'pushed_authorization_request_endpoint';
    (Object.prototype as unknown as Record<string, unknown>)[key] = 'https://attacker.example/par';
    try {
      const stub = createStubFetch({
        [AS_METADATA_URL]: () =>
          json({ issuer: AS, authorization_endpoint: AUTHZ_URL, token_endpoint: TOKEN_URL }),
      });
      await expect(fetchAuthorizationServerMetadata(AS, stub.fetchImpl)).rejects.toMatchObject({
        context: { reason: 'missing_endpoint' },
      });
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>)[key];
    }
  });
});

describe('fetchIssuerMetadata の authorization_servers 読み出し', () => {
  test('告知された AS 群を返す', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
    });
    const endpoints = await fetchIssuerMetadata(ISSUER, stub.fetchImpl);
    expect(endpoints.authorizationServers).toEqual([AS]);
  });

  test('未告知でも authorizationServers を own キーとして持つ（汚染値に抜けない）', async () => {
    (Object.prototype as unknown as Record<string, unknown>).authorizationServers = [
      'https://attacker.example',
    ];
    try {
      const stub = createStubFetch({ [ISSUER_METADATA_URL]: () => issuerMetadataResponse() });
      const endpoints = await fetchIssuerMetadata(ISSUER, stub.fetchImpl);
      expect(Object.hasOwn(endpoints, 'authorizationServers')).toBe(true);
      expect(endpoints.authorizationServers).toBeUndefined();
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>).authorizationServers;
    }
  });

  test('空配列は「告知が無い」と同じ扱いにする', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [] }),
    });
    const endpoints = await fetchIssuerMetadata(ISSUER, stub.fetchImpl);
    expect(endpoints.authorizationServers).toBeUndefined();
  });

  test('非 HTTPS の AS 識別子は拒否する（AS Metadata を平文で取りに行かせない）', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () =>
        issuerMetadataResponse({ authorization_servers: ['http://as.example.eu'] }),
    });
    await expect(fetchIssuerMetadata(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'non_https_authorization_server' },
    });
  });

  test('配列でない authorization_servers は invalid_metadata', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: AS }),
    });
    await expect(fetchIssuerMetadata(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'invalid_metadata' },
    });
  });
});
