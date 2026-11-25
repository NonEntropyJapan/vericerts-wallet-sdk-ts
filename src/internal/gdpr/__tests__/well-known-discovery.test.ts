/**
 * discoverDsrEndpoint / discoverDpoContact の well-known 発見検証。
 *
 * `globalThis.fetch` を差し替えてモックし、正常系（必須 / 任意フィールド）・異常系
 * （ドメイン不正 / 4xx / 5xx / Content-Type 不正 / 不正 JSON / スキーマ不正 / 非 HTTPS URL /
 * タイムアウト / 非 HTTPS リダイレクト）を確認する。
 *
 * エラーコード粒度（10605 / 10606）: 取得失敗（4xx・5xx / タイムアウト /
 * ネットワークエラー / 非 HTTPS リダイレクト）は `GDPR_DISCOVERY_FETCH_FAILED`（10605）、
 * ドメイン不正 / Content-Type 不一致 / JSON parse 失敗 / スキーマ不正は `GDPR_DISCOVERY_INVALID`
 * （10606）になることを検証する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../errors.js';
import { discoverDpoContact, discoverDsrEndpoint } from '../well-known-discovery.js';

const DOMAIN = 'issuer.example.com';
const DSR_URL = 'https://issuer.example.com/.well-known/dsr-endpoint';
const DPO_URL = 'https://issuer.example.com/.well-known/dpo-contact';

/** モックレスポンスを構築するヘルパ（method-web の resolve テストと同じ方針）。 */
function mockResponse(opts: {
  body: string;
  status?: number;
  contentType?: string | null;
  url?: string;
}): Response {
  const headers = new Headers();
  if (opts.contentType !== null && opts.contentType !== undefined) {
    headers.set('content-type', opts.contentType);
  }
  const response = new Response(opts.body, { status: opts.status ?? 200, headers });
  // Response の url は読み取り専用のため defineProperty で上書きする。
  Object.defineProperty(response, 'url', { value: opts.url ?? DSR_URL, configurable: true });
  return response;
}

const originalFetch = globalThis.fetch;

/** モック実装を `globalThis.fetch` に差し替える（`preconnect` 等を含む型差を吸収）。 */
function mockFetch(
  impl: (input: string | URL | Request, init?: RequestInit) => Promise<Response>,
): void {
  globalThis.fetch = impl as unknown as typeof fetch;
}

/** JSON レスポンスを返すモックを差し替える。 */
function mockJson(body: unknown, url = DSR_URL): void {
  mockFetch(async () =>
    mockResponse({ body: JSON.stringify(body), contentType: 'application/json', url }),
  );
}

/** reject が指定コードの VericertsError であることを検証する。 */
async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('discoverDsrEndpoint 正常系', () => {
  it('必須 dsrEndpoint のみをパースし、正しい URL を GET する', async () => {
    let calledUrl = '';
    mockFetch(async (input) => {
      calledUrl = typeof input === 'string' ? input : input.toString();
      return mockResponse({
        body: JSON.stringify({ dsrEndpoint: 'https://issuer.example.com/dsr' }),
        contentType: 'application/json',
      });
    });

    const meta = await discoverDsrEndpoint(DOMAIN);
    expect(calledUrl).toBe(DSR_URL);
    expect(meta.dsrEndpoint).toBe('https://issuer.example.com/dsr');
    expect(meta.supportedRights).toBeUndefined();
    expect(meta.formats).toBeUndefined();
  });

  it('任意フィールド supportedRights / formats を保持する', async () => {
    mockJson({
      dsrEndpoint: 'https://issuer.example.com/dsr',
      supportedRights: ['access', 'erasure'],
      formats: ['application/json'],
    });

    const meta = await discoverDsrEndpoint(DOMAIN);
    expect(meta.supportedRights).toEqual(['access', 'erasure']);
    expect(meta.formats).toEqual(['application/json']);
  });

  it('charset 付き Content-Type でも取得できる', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify({ dsrEndpoint: 'https://issuer.example.com/dsr' }),
        contentType: 'application/json; charset=utf-8',
      }),
    );
    const meta = await discoverDsrEndpoint(DOMAIN);
    expect(meta.dsrEndpoint).toBe('https://issuer.example.com/dsr');
  });

  it('host:port ドメインを受理する', async () => {
    let calledUrl = '';
    mockFetch(async (input) => {
      calledUrl = typeof input === 'string' ? input : input.toString();
      return mockResponse({
        body: JSON.stringify({ dsrEndpoint: 'https://issuer.example.com/dsr' }),
        contentType: 'application/json',
        url: 'https://issuer.example.com:8443/.well-known/dsr-endpoint',
      });
    });
    await discoverDsrEndpoint('issuer.example.com:8443');
    expect(calledUrl).toBe('https://issuer.example.com:8443/.well-known/dsr-endpoint');
  });
});

describe('discoverDsrEndpoint 異常系', () => {
  it('空ドメインは 10606', async () => {
    await expectRejectCode(discoverDsrEndpoint(''), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('スキーム付きドメインは 10606', async () => {
    await expectRejectCode(
      discoverDsrEndpoint('https://issuer.example.com'),
      ErrorCodes.GDPR_DISCOVERY_INVALID,
    );
  });

  it('パス付きドメインは 10606', async () => {
    await expectRejectCode(
      discoverDsrEndpoint('issuer.example.com/foo'),
      ErrorCodes.GDPR_DISCOVERY_INVALID,
    );
  });

  it('HTTP 404 は 10605', async () => {
    mockFetch(async () => mockResponse({ body: '', status: 404 }));
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_FETCH_FAILED);
  });

  it('HTTP 500 は 10605', async () => {
    mockFetch(async () => mockResponse({ body: '', status: 500 }));
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_FETCH_FAILED);
  });

  it('ネットワークエラーは 10605', async () => {
    mockFetch(async () => {
      throw new TypeError('network');
    });
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_FETCH_FAILED);
  });

  it('タイムアウト（abort）は 10605', async () => {
    // 実 10 秒待たず、AbortController.abort() 時の AbortError 拒否を即時に再現する
    // （method-web / method-ipid の resolve テストと同じ方針）。
    mockFetch(async () => {
      throw new DOMException('The operation was aborted.', 'AbortError');
    });
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_FETCH_FAILED);
  });

  it('非 HTTPS リダイレクト後は 10605', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify({ dsrEndpoint: 'https://issuer.example.com/dsr' }),
        contentType: 'application/json',
        url: 'http://evil.example.com/.well-known/dsr-endpoint',
      }),
    );
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_FETCH_FAILED);
  });

  it('Content-Type 不一致は 10606', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify({ dsrEndpoint: 'https://issuer.example.com/dsr' }),
        contentType: 'text/html',
      }),
    );
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('不正 JSON は 10606', async () => {
    mockFetch(async () => mockResponse({ body: '{not json', contentType: 'application/json' }));
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('配列 JSON（非オブジェクト）は 10606', async () => {
    mockJson([1, 2, 3]);
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('dsrEndpoint 欠落は 10606', async () => {
    mockJson({ supportedRights: ['access'] });
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('dsrEndpoint が非 HTTPS は 10606', async () => {
    mockJson({ dsrEndpoint: 'http://issuer.example.com/dsr' });
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('supportedRights に非文字列が混じると 10606', async () => {
    mockJson({ dsrEndpoint: 'https://issuer.example.com/dsr', supportedRights: ['access', 1] });
    await expectRejectCode(discoverDsrEndpoint(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });
});

describe('discoverDpoContact 正常系', () => {
  it('必須 email のみをパースする', async () => {
    let calledUrl = '';
    mockFetch(async (input) => {
      calledUrl = typeof input === 'string' ? input : input.toString();
      return mockResponse({
        body: JSON.stringify({ email: 'dpo@example.com' }),
        contentType: 'application/json',
        url: DPO_URL,
      });
    });

    const meta = await discoverDpoContact(DOMAIN);
    expect(calledUrl).toBe(DPO_URL);
    expect(meta.email).toBe('dpo@example.com');
    expect(meta.name).toBeUndefined();
  });

  it('任意フィールド name / phone / address / url を保持する', async () => {
    mockJson(
      {
        email: 'dpo@example.com',
        name: 'DPO Office',
        phone: '+49-30-000000',
        address: 'Berlin',
        url: 'https://issuer.example.com/dpo',
      },
      DPO_URL,
    );

    const meta = await discoverDpoContact(DOMAIN);
    expect(meta.name).toBe('DPO Office');
    expect(meta.phone).toBe('+49-30-000000');
    expect(meta.address).toBe('Berlin');
    expect(meta.url).toBe('https://issuer.example.com/dpo');
  });
});

describe('discoverDpoContact 異常系', () => {
  it('email 欠落は 10606', async () => {
    mockJson({ name: 'DPO Office' }, DPO_URL);
    await expectRejectCode(discoverDpoContact(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('email が空文字は 10606', async () => {
    mockJson({ email: '' }, DPO_URL);
    await expectRejectCode(discoverDpoContact(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('url が非 HTTPS は 10606', async () => {
    mockJson({ email: 'dpo@example.com', url: 'http://issuer.example.com/dpo' }, DPO_URL);
    await expectRejectCode(discoverDpoContact(DOMAIN), ErrorCodes.GDPR_DISCOVERY_INVALID);
  });

  it('HTTP 404 は 10605', async () => {
    mockFetch(async () => mockResponse({ body: '', status: 404, url: DPO_URL }));
    await expectRejectCode(discoverDpoContact(DOMAIN), ErrorCodes.GDPR_DISCOVERY_FETCH_FAILED);
  });
});
