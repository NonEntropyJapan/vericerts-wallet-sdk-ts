/**
 * `fetchIssuerMetadata` のテスト。
 *
 * Issuer Metadata 取得はすべての失敗を `ISSUER_COMMUNICATION_FAILED`（3004）へ正規化する。
 * 非 HTTPS の発行者 URL は**通信そのものを発生させずに**拒否されること、リダイレクトで
 * HTTPS を外れた場合と発見したエンドポイントが非 HTTPS の場合も拒否されることを検証する。
 */

import { describe, expect, test } from 'bun:test';
import { fetchIssuerMetadata } from '../../../../../exports/experimental/oid4vci.js';
import { VericertsError } from '../../../../errors.js';
import {
  CREDENTIAL_URL,
  createStubFetch,
  ISSUER,
  jsonResponse,
  METADATA_URL,
  metadataResponse,
  TOKEN_URL,
} from './issuance-fixtures.js';

/** 最終 URL（`response.url`）を差し替えた応答を作る（リダイレクト後の観測を模す）。 */
function withFinalUrl(response: Response, url: string): Response {
  Object.defineProperty(response, 'url', { value: url, configurable: true });
  return response;
}

/** 3004 であることを表明する（poison pill 付き）。 */
async function expectIssuerCommunicationFailed(run: () => Promise<unknown>): Promise<void> {
  try {
    await run();
    throw new Error('should throw');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe('3004');
  }
}

describe('fetchIssuerMetadata', () => {
  test('正常系: credential_endpoint / token_endpoint を返す', async () => {
    const stub = createStubFetch({ [METADATA_URL]: metadataResponse });
    const endpoints = await fetchIssuerMetadata(ISSUER, stub.fetchImpl);
    expect(endpoints.credentialEndpoint).toBe(CREDENTIAL_URL);
    expect(endpoints.tokenEndpoint).toBe(TOKEN_URL);
    expect(stub.calls.map((call) => call.url)).toEqual([METADATA_URL]);
  });

  test('末尾スラッシュ付きの credential_issuer でも well-known URL は 1 本になる', async () => {
    const stub = createStubFetch({ [METADATA_URL]: metadataResponse });
    await fetchIssuerMetadata(`${ISSUER}/`, stub.fetchImpl);
    expect(stub.calls[0]?.url).toBe(METADATA_URL);
  });

  test('非 HTTPS の credential_issuer は 3004（fetch を発生させない）', async () => {
    const stub = createStubFetch({ [METADATA_URL]: metadataResponse });
    await expectIssuerCommunicationFailed(() =>
      fetchIssuerMetadata('http://issuer.example.eu', stub.fetchImpl),
    );
    expect(stub.calls).toHaveLength(0);
  });

  test('HTTP 非 2xx は 3004', async () => {
    const stub = createStubFetch({
      [METADATA_URL]: () => new Response('', { status: 500 }),
    });
    await expectIssuerCommunicationFailed(() => fetchIssuerMetadata(ISSUER, stub.fetchImpl));
  });

  test('JSON として解釈できない本文は 3004', async () => {
    // Content-Type は JSON にしておく。付けないと（既定 `text/plain`）入口の Content-Type 検査で
    // 落ちてしまい、本テストが固定したい `invalid_json` 分岐を通らなくなる。
    const stub = createStubFetch({
      [METADATA_URL]: () =>
        new Response('<html>', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    });
    await expectIssuerCommunicationFailed(() => fetchIssuerMetadata(ISSUER, stub.fetchImpl));
  });

  test('credential_endpoint を欠く Metadata は 3004', async () => {
    const stub = createStubFetch({
      [METADATA_URL]: () => jsonResponse({ token_endpoint: TOKEN_URL }),
    });
    await expectIssuerCommunicationFailed(() => fetchIssuerMetadata(ISSUER, stub.fetchImpl));
  });

  test('非 HTTPS の token_endpoint を宣言する Metadata は 3004', async () => {
    const stub = createStubFetch({
      [METADATA_URL]: () =>
        jsonResponse({
          credential_endpoint: CREDENTIAL_URL,
          token_endpoint: 'http://issuer.example.eu/token',
        }),
    });
    await expectIssuerCommunicationFailed(() => fetchIssuerMetadata(ISSUER, stub.fetchImpl));
  });

  test('リダイレクト後の最終 URL が http なら 3004', async () => {
    const stub = createStubFetch({
      [METADATA_URL]: () => withFinalUrl(metadataResponse(), 'http://attacker.example/metadata'),
    });
    await expectIssuerCommunicationFailed(() => fetchIssuerMetadata(ISSUER, stub.fetchImpl));
  });

  test('ネットワークエラーは 3004', async () => {
    const fetchImpl = () => Promise.reject(new Error('network down'));
    await expectIssuerCommunicationFailed(() => fetchIssuerMetadata(ISSUER, fetchImpl));
  });
});
