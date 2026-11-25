/**
 * OID4VCI Token Endpoint クライアントのテスト。
 *
 * `fetch` をスタブして以下を検証する:
 * - pre-authorized_code フロー（grant_type / pre-authorized_code / tx_code の送信、レスポンス mapping）
 * - authorization_code フロー（code / code_verifier / redirect_uri / client_id の送信）
 *   （Attestation-Based Client Auth の `client_assertion` は
 *   `oid4vci/__tests__/token/oid4vci-token.client-auth.test.ts`）
 * - エラーレスポンス処理（HTTP 非 2xx / ネットワーク失敗 / レスポンス不正 → 8010）
 * - PKCE（RFC 7636 S256）の code_verifier / code_challenge 生成
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createInMemoryMetrics, MetricNames } from '../../../observability/metrics.js';
import {
  type FetchCall,
  stubFetchOk,
  VALID_TOKEN_BODY,
} from '../../oid4vci/__tests__/token/token-fixtures.js';
import { generatePkcePair } from '../../oid4vci/oid4vci-pkce.js';
import {
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_PRE_AUTHORIZED_CODE,
  requestTokenAuthorizationCode,
  requestTokenPreAuthorized,
} from '../../oid4vci/token/oid4vci-token.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/**
 * 任意の fetch 実装をグローバルに差し込む（型は test 用に緩める）。
 * 成功レスポンス以外（非 2xx / 本文不正）を返す「エラーレスポンス処理」用。
 */
function setFetch(impl: (url: string, init: RequestInit) => Promise<Response>): void {
  globalThis.fetch = impl as unknown as typeof fetch;
}

describe('requestTokenPreAuthorized', () => {
  it('pre-authorized_code と tx_code を form-urlencoded で送り TokenResponse に mapping する', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    const res = await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      preAuthorizedCode: 'SplxlOBeZQQYbYS6WxSbIA',
      txCode: '493536',
    });

    expect(res).toEqual({
      accessToken: VALID_TOKEN_BODY.access_token,
      tokenType: 'Bearer',
      expiresIn: 3600,
      cNonce: VALID_TOKEN_BODY.c_nonce,
      cNonceExpiresIn: 86400,
    });

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.url).toBe(TOKEN_ENDPOINT);
    expect(call?.init.method).toBe('POST');
    expect(call?.init.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect(call?.body.get('grant_type')).toBe(GRANT_TYPE_PRE_AUTHORIZED_CODE);
    expect(call?.body.get('pre-authorized_code')).toBe('SplxlOBeZQQYbYS6WxSbIA');
    expect(call?.body.get('tx_code')).toBe('493536');
  });

  it('tx_code 省略時は tx_code パラメータを送らない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      preAuthorizedCode: 'code-without-pin',
    });

    expect(calls[0]?.body.has('tx_code')).toBe(false);
    expect(calls[0]?.body.get('pre-authorized_code')).toBe('code-without-pin');
  });

  it('expires_in / c_nonce_expires_in が数値文字列でも受理する', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls, { ...VALID_TOKEN_BODY, expires_in: '3600', c_nonce_expires_in: '86400' });

    const res = await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      preAuthorizedCode: 'c',
    });

    expect(res.expiresIn).toBe(3600);
    expect(res.cNonceExpiresIn).toBe(86400);
  });
});

describe('requestTokenAuthorizationCode', () => {
  it('code / code_verifier / redirect_uri / client_id を送る', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'auth-code-123',
      codeVerifier: 'verifier-xyz',
      redirectUri: 'com.example.wallet://cb',
      clientId: 'wallet-client',
    });

    const body = calls[0]?.body;
    expect(body?.get('grant_type')).toBe(GRANT_TYPE_AUTHORIZATION_CODE);
    expect(body?.get('code')).toBe('auth-code-123');
    expect(body?.get('code_verifier')).toBe('verifier-xyz');
    expect(body?.get('redirect_uri')).toBe('com.example.wallet://cb');
    expect(body?.get('client_id')).toBe('wallet-client');
  });

  it('redirect_uri / client_id 省略時はそれらのパラメータを送らない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'auth-code',
      codeVerifier: 'verifier',
    });

    expect(calls[0]?.body.has('redirect_uri')).toBe(false);
    expect(calls[0]?.body.has('client_id')).toBe(false);
  });
});

describe('エラーレスポンス処理', () => {
  it('HTTP 400（invalid_grant 等の OAuth エラー）は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    setFetch(
      async () =>
        new Response(JSON.stringify({ error: 'invalid_grant' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }),
    );

    const promise = requestTokenPreAuthorized(TOKEN_ENDPOINT, { preAuthorizedCode: 'bad' });
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });

  it('ネットワーク失敗は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    setFetch(async () => {
      throw new TypeError('network down');
    });

    const promise = requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'c',
      codeVerifier: 'v',
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });

  it('レスポンス JSON が不正な場合は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    setFetch(
      async () =>
        new Response('not-json', {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    );

    const promise = requestTokenPreAuthorized(TOKEN_ENDPOINT, { preAuthorizedCode: 'c' });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });

  it('必須フィールド（access_token）欠落は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    const { access_token, ...rest } = VALID_TOKEN_BODY;
    void access_token;
    setFetch(
      async () =>
        new Response(JSON.stringify(rest), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    );

    const promise = requestTokenPreAuthorized(TOKEN_ENDPOINT, { preAuthorizedCode: 'c' });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });

  it('c_nonce_expires_in が非数値文字列の場合は TOKEN_REQUEST_FAILED(8010) になる', async () => {
    setFetch(
      async () =>
        new Response(JSON.stringify({ ...VALID_TOKEN_BODY, c_nonce_expires_in: 'soon' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    );

    const promise = requestTokenPreAuthorized(TOKEN_ENDPOINT, { preAuthorizedCode: 'c' });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
  });
});

describe('generatePkcePair', () => {
  it('S256 の code_challenge が code_verifier の SHA-256 base64url と一致する', () => {
    const pair = generatePkcePair();

    expect(pair.codeChallengeMethod).toBe('S256');
    expect(pair.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(pair.codeVerifier.length).toBeLessThanOrEqual(128);

    const expectedChallenge = base64urlnopad.encode(
      sha256(new TextEncoder().encode(pair.codeVerifier)),
    );
    expect(pair.codeChallenge).toBe(expectedChallenge);
  });

  it('RFC 7636 付録 B のテストベクタを再現する', () => {
    // RFC 7636 Appendix B: code_verifier の例から code_challenge を導出する。
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = base64urlnopad.encode(sha256(new TextEncoder().encode(verifier)));
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('呼び出すたびに異なる code_verifier を生成する', () => {
    const a = generatePkcePair();
    const b = generatePkcePair();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
  });

  it('code_verifier は base64url 文字のみで構成される', () => {
    const { codeVerifier } = generatePkcePair();
    expect(codeVerifier).toMatch(/^[A-Za-z0-9\-_]+$/);
  });
});

describe('oid4vci_token_duration_seconds のメトリクス配線', () => {
  it('pre-authorized_code フローで flow=pre-auth を記録する', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);
    const { metrics, snapshot } = createInMemoryMetrics();

    await requestTokenPreAuthorized(
      TOKEN_ENDPOINT,
      { preAuthorizedCode: 'SplxlOBeZQQYbYS6WxSbIA' },
      metrics,
    );

    const histogram = snapshot().histograms.find(
      (h) => h.name === MetricNames.OID4VCI_TOKEN_DURATION_SECONDS,
    );
    expect(histogram?.labels).toEqual({ flow: 'pre-auth' });
    expect(histogram?.count).toBe(1);
  });

  it('authorization_code フローで flow=auth-code を記録する', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);
    const { metrics, snapshot } = createInMemoryMetrics();

    await requestTokenAuthorizationCode(
      TOKEN_ENDPOINT,
      { code: 'auth-code-123', codeVerifier: 'verifier-xyz' },
      metrics,
    );

    const histogram = snapshot().histograms.find(
      (h) => h.name === MetricNames.OID4VCI_TOKEN_DURATION_SECONDS,
    );
    expect(histogram?.labels).toEqual({ flow: 'auth-code' });
    expect(histogram?.count).toBe(1);
  });

  it('metrics 未指定でも従来どおり動作する', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);
    await expect(
      requestTokenPreAuthorized(TOKEN_ENDPOINT, { preAuthorizedCode: 'code' }),
    ).resolves.toBeDefined();
  });
});
