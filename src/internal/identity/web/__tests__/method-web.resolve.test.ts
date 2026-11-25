/**
 * resolveDidWeb / MethodWeb.resolve の HTTPS 解決検証。
 *
 * `globalThis.fetch` を差し替えてモックし、正常系（did+json / json）・
 * 異常系（4xx / 5xx / Content-Type 不正 / 不正 JSON / 構造不正 / タイムアウト /
 * 非 HTTPS リダイレクト）を確認する。
 *
 * エラーコード粒度（2003 / 2010）: 取得失敗（4xx・5xx / タイムアウト /
 * ネットワークエラー / 非 HTTPS リダイレクト）は `DID_NOT_FOUND`（2003）、Content-Type
 * 不一致 / JSON parse 失敗 / スキーマ不正は `DID_DOC_INVALID`（2010）、DID 文字列形式不正は
 * `INVALID_DID`（2001）になることを検証する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import type { DIDDocument } from '../../did.js';
import { MethodWeb, resolveDidWeb } from '../method-web.js';

/** `resolveDidWeb` の reject が指定コードの VericertsError であることを検証する。 */
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

const DID = 'did:web:example.com';
const EXPECTED_URL = 'https://example.com/.well-known/did.json';

const SAMPLE_DOC: DIDDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: DID,
  verificationMethod: [
    {
      id: `${DID}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: DID,
      publicKeyMultibase: 'z6MkExample',
    },
  ],
  authentication: [`${DID}#key-1`],
  assertionMethod: [`${DID}#key-1`],
};

/** モックレスポンスを構築するヘルパ。 */
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
  const status = opts.status ?? 200;
  // Response の url は読み取り専用のため defineProperty で上書きする。
  const response = new Response(opts.body, { status, headers });
  Object.defineProperty(response, 'url', {
    value: opts.url ?? EXPECTED_URL,
    configurable: true,
  });
  return response;
}

const originalFetch = globalThis.fetch;

/** モック実装を `globalThis.fetch` に差し替える（`preconnect` 等を含む型差を吸収）。 */
function mockFetch(
  impl: (input: string | URL | Request, init?: RequestInit) => Promise<Response>,
): void {
  globalThis.fetch = impl as unknown as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('resolveDidWeb 正常系', () => {
  it('application/did+json で取得し DIDDocument を返す', async () => {
    let calledUrl = '';
    mockFetch(async (input) => {
      calledUrl = typeof input === 'string' ? input : input.toString();
      return mockResponse({
        body: JSON.stringify(SAMPLE_DOC),
        contentType: 'application/did+json',
      });
    });

    const doc = await resolveDidWeb(DID);
    expect(calledUrl).toBe(EXPECTED_URL);
    expect(doc.id).toBe(DID);
    expect(doc.verificationMethod[0]?.type).toBe('Ed25519VerificationKey2020');
  });

  it('application/json （charset 付き）でも取得できる', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify(SAMPLE_DOC),
        contentType: 'application/json; charset=utf-8',
      }),
    );

    const doc = await resolveDidWeb(DID);
    expect(doc.id).toBe(DID);
  });

  it('MethodWeb.resolve も同様に解決する', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify(SAMPLE_DOC),
        contentType: 'application/did+json',
      }),
    );

    const doc = await new MethodWeb().resolve(DID);
    expect(doc.id).toBe(DID);
  });
});

describe('resolveDidWeb 異常系', () => {
  it('HTTP 404 は 2003（取得失敗）', async () => {
    mockFetch(async () =>
      mockResponse({
        body: 'Not Found',
        status: 404,
        contentType: 'text/plain',
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_NOT_FOUND);
  });

  it('HTTP 500 は 2003（取得失敗）', async () => {
    mockFetch(async () =>
      mockResponse({
        body: 'error',
        status: 500,
        contentType: 'application/json',
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_NOT_FOUND);
  });

  it('Content-Type が text/html は 2010（ドキュメント不正）', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify(SAMPLE_DOC),
        contentType: 'text/html',
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_DOC_INVALID);
  });

  it('Content-Type ヘッダ欠落は 2010（ドキュメント不正）', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify(SAMPLE_DOC),
        contentType: null,
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_DOC_INVALID);
  });

  it('不正な JSON は 2010（ドキュメント不正）', async () => {
    mockFetch(async () =>
      mockResponse({
        body: '{ not json',
        contentType: 'application/json',
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_DOC_INVALID);
  });

  it('id を欠く DID Document は 2010（ドキュメント不正）', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify({ '@context': ['https://www.w3.org/ns/did/v1'] }),
        contentType: 'application/did+json',
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_DOC_INVALID);
  });

  it('JSON 配列（非オブジェクト）は 2010（ドキュメント不正）', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify([SAMPLE_DOC]),
        contentType: 'application/json',
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_DOC_INVALID);
  });

  it('doc.id が解決対象 DID と不一致なら 2010（取り違え／なりすまし拒否）', async () => {
    // 信頼ドメインを解決したのに別 DID の文書が返るケース。id 検証がないと成功扱いになる。
    // 実際の取り違え攻撃文書を模し、内部参照も攻撃者 DID に揃える。
    const attackerDid = 'did:web:attacker.example';
    const otherDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: attackerDid,
      verificationMethod: [
        {
          id: `${attackerDid}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: attackerDid,
          publicKeyMultibase: 'z6MkExample',
        },
      ],
      authentication: [`${attackerDid}#key-1`],
      assertionMethod: [`${attackerDid}#key-1`],
    };
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify(otherDoc),
        contentType: 'application/did+json',
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_DOC_INVALID);
  });

  it('doc.id が解決対象 DID の近似（パス/フラグメント付き）でも 2010 で拒否', async () => {
    // 完全一致照合（!==）の境界。前方一致では通過してしまう近似 id を拒否することを確認する。
    const nearMissIds = [`${DID}:extra`, `${DID}#key-1`, 'did:web:example.com.attacker'];
    for (const nearMissId of nearMissIds) {
      mockFetch(async () =>
        mockResponse({
          body: JSON.stringify({ ...SAMPLE_DOC, id: nearMissId }),
          contentType: 'application/did+json',
        }),
      );

      await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_DOC_INVALID);
    }
  });

  it('ポート表記の揺れ（%3A vs 生コロン）は完全一致しないため 2010（fail-closed 設計の固定）', async () => {
    // 入力 did:web:host%3A8443 と did:web:host:8443 は同一 URL に解決されるが、
    // id 照合はバイト単位完全一致のため不一致は拒否される（method-web.ts の設計判断）。
    const encodedDid = 'did:web:example.com%3A8443';
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify({ ...SAMPLE_DOC, id: 'did:web:example.com:8443' }),
        contentType: 'application/did+json',
        url: 'https://example.com:8443/.well-known/did.json',
      }),
    );

    await expectRejectCode(resolveDidWeb(encodedDid), ErrorCodes.DID_DOC_INVALID);
  });

  it('非 HTTPS へのリダイレクト（最終 URL が http）は 2003（取得失敗）', async () => {
    mockFetch(async () =>
      mockResponse({
        body: JSON.stringify(SAMPLE_DOC),
        contentType: 'application/did+json',
        url: 'http://example.com/.well-known/did.json',
      }),
    );

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_NOT_FOUND);
  });

  it('fetch がタイムアウト（abort）すると 2003（取得失敗）', async () => {
    // 実 10 秒待たず、AbortController.abort() 時の AbortError 拒否を即時に再現する。
    mockFetch(async () => {
      throw new DOMException('The operation was aborted.', 'AbortError');
    });

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_NOT_FOUND);
  });

  it('fetch のネットワークエラーは 2003（取得失敗）', async () => {
    mockFetch(async () => {
      throw new TypeError('Failed to fetch');
    });

    await expectRejectCode(resolveDidWeb(DID), ErrorCodes.DID_NOT_FOUND);
  });

  it('DID 形式不正（プレフィックス不正）は fetch せず 2001', async () => {
    let called = false;
    mockFetch(async () => {
      called = true;
      return mockResponse({ body: '{}', contentType: 'application/json' });
    });

    await expectRejectCode(resolveDidWeb('did:key:z6Mk'), ErrorCodes.INVALID_DID);
    expect(called).toBe(false);
  });
});

describe('MethodWeb ライフサイクル', () => {
  it('method() は web を返す', () => {
    expect(new MethodWeb().method()).toBe('web');
  });

  it('create は 2002 を投げる', async () => {
    const method = new MethodWeb();
    await expect(
      method.create({ keyType: 'Ed25519', publicKey: new Uint8Array(32) }),
    ).rejects.toThrow(new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED));
  });

  it('update は 2002 を投げる', async () => {
    await expect(new MethodWeb().update(DID, {})).rejects.toThrow(
      new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED),
    );
  });

  it('deactivate は 2002 を投げる', async () => {
    await expect(new MethodWeb().deactivate(DID)).rejects.toThrow(
      new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED),
    );
  });
});
