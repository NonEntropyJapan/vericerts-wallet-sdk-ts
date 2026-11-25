/**
 * Token / Credential Request への相関 ID 伝播。
 *
 * - `correlationContext` 指定時に `traceparent` / `X-Request-Id`（+ `tracestate`）が載ること
 * - 未指定・形が壊れた値では相関ヘッダを出さないこと（既存呼び出しの後方互換 / fail-safe）
 *
 * 置き場所は同じ 2 関数を検証する `oid4vci-token.test.ts` / `oid4vci.credential.test.ts` に揃える。
 * PAR 経路の同じ不変条件は `oid4vci/par/__tests__/par-correlation.test.ts` が持つ。
 */

import { describe, expect, test } from 'bun:test';
import type { FetchLike } from '../../../fetch-di.js';
import { createCorrelationContext } from '../../../observability/correlation.js';
import { VALID_TOKEN_BODY } from '../../oid4vci/__tests__/token/token-fixtures.js';
import { requestCredential } from '../../oid4vci/oid4vci.js';
import {
  requestTokenAuthorizationCode,
  requestTokenPreAuthorized,
} from '../../oid4vci/token/oid4vci-token.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';
const CREDENTIAL_ENDPOINT = 'https://issuer.example.com/credential';
const CONTEXT = createCorrelationContext({ requestId: 'popup-click-42', tracestate: 'rojo=1' });

/** 送信ヘッダを記録するスタブ（`body` をそのまま 200 で返す）。 */
function stub(body: unknown): { fetchImpl: FetchLike; headers: Record<string, string>[] } {
  const headers: Record<string, string>[] = [];
  const fetchImpl: FetchLike = (_url, init) => {
    headers.push(init.headers);
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  };
  return { fetchImpl, headers };
}

/** Credential Request の必須オプション（相関 ID と fetch シームは呼び出し側で足す）。 */
const credentialOptions = {
  credentialEndpoint: CREDENTIAL_ENDPOINT,
  accessToken: 'access-token-value',
  format: 'dc+sd-jwt',
  credentialDefinition: { type: ['UniversityDegree'] },
  proofJwt: 'header.payload.sig',
} as const;

describe('OID4VCI の相関 ID 伝播', () => {
  test('pre-authorized_code の Token Request に相関ヘッダが載る', async () => {
    const { fetchImpl, headers } = stub(VALID_TOKEN_BODY);
    await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      preAuthorizedCode: 'pre-auth-code',
      correlationContext: CONTEXT,
      fetchImpl,
    });
    expect(headers[0]?.traceparent).toBe(CONTEXT.traceparent);
    expect(headers[0]?.['X-Request-Id']).toBe(CONTEXT.requestId);
    expect(headers[0]?.tracestate).toBe('rojo=1');
  });

  test('authorization_code の Token Request と Credential Request にも同じ値が載る', async () => {
    const token = stub(VALID_TOKEN_BODY);
    await requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'authz-code',
      codeVerifier: 'verifier',
      correlationContext: CONTEXT,
      fetchImpl: token.fetchImpl,
    });
    const credential = stub({ credential: 'vc-value' });
    await requestCredential({
      ...credentialOptions,
      correlationContext: CONTEXT,
      fetchImpl: credential.fetchImpl,
    });
    // 同じ受領フローの 3 経路が 1 本のトレースに繋がることを確認する。
    for (const headers of [token.headers[0], credential.headers[0]]) {
      expect(headers?.traceparent).toBe(CONTEXT.traceparent);
      expect(headers?.['X-Request-Id']).toBe(CONTEXT.requestId);
    }
  });

  test.each([
    ['未指定', undefined],
    ['形が壊れた値', { traceparent: 123 } as never],
  ])('%s のときは相関ヘッダを出さない', async (_label, correlationContext) => {
    const token = stub(VALID_TOKEN_BODY);
    await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      preAuthorizedCode: 'pre-auth-code',
      correlationContext,
      fetchImpl: token.fetchImpl,
    });
    const credential = stub({ credential: 'vc-value' });
    await requestCredential({
      ...credentialOptions,
      correlationContext,
      fetchImpl: credential.fetchImpl,
    });
    for (const headers of [token.headers[0], credential.headers[0]]) {
      // 要求自体は出ている（ヘッダが無いことの検査が空振りしていないことの担保）。
      expect(headers?.Accept).toBe('application/json');
      expect(headers?.traceparent).toBeUndefined();
      expect(headers?.['X-Request-Id']).toBeUndefined();
    }
  });
});
