/**
 * `fetchDidLog` の入口検査（本文バイト上限・最終 URL の HTTPS 判定・Content-Type）と
 * fetch DI seam の回帰テスト。
 *
 * did:webvh の `domain` は受領した VC の `iss` 由来で**攻撃者が選べる**ため、DID Log を上限なしに
 * 読むと提示された VC 一つでウォレットのメモリを枯渇させられる。上限は
 * `http/body-limit.ts` の `MAX_DOCUMENT_BYTES`（1 MiB）で、宣言値（`content-length`）と実バイト数の
 * 双方に課す。
 *
 * 同じ理由で Content-Type も検査する。攻撃者が選んだホストが返す `text/html` のエラーページを
 * JSONL の行パーサへ渡さないためである。加えて、ホストアプリが証明書ピン留め済みの `fetch` を
 * 注入できる seam（`fetchFn`）が実際に使われることを押さえる。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MAX_DOCUMENT_BYTES } from '../../../http/body-limit.js';
import { fetchDidLog } from '../did-url.js';

const LOG_URL = 'https://issuer.example/.well-known/did.jsonl';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** 指定の本文・ヘッダ・最終 URL を返す fetch モック。 */
function mockResponse(body: string, init?: ResponseInit, finalUrl?: string): void {
  globalThis.fetch = (async () => {
    const response = new Response(body, { status: 200, ...init });
    // Bun の `Response` は本文から `content-type` を補わないため、DID Log の既定 media type を
    // 置く（Content-Type そのものを検証するテストは `init.headers` で上書きする）。
    if (response.headers.get('content-type') === null) {
      response.headers.set('content-type', 'application/jsonl');
    }
    if (finalUrl !== undefined) {
      Object.defineProperty(response, 'url', { value: finalUrl });
    }
    return response;
  }) as unknown as typeof fetch;
}

/** `fetchDidLog` が投げた `VericertsError` を捕まえる。 */
async function catchFetchDidLog(): Promise<VericertsError | undefined> {
  try {
    await fetchDidLog(LOG_URL);
    return undefined;
  } catch (error) {
    return error instanceof VericertsError ? error : undefined;
  }
}

describe('fetchDidLog の本文バイト上限', () => {
  it('上限以内の DID Log はそのまま返す', async () => {
    mockResponse('{"versionId":"1"}\n');
    expect(await fetchDidLog(LOG_URL)).toBe('{"versionId":"1"}\n');
  });

  it('MAX_DOCUMENT_BYTES を超える本文は 2003 で拒否する', async () => {
    mockResponse('a'.repeat(MAX_DOCUMENT_BYTES + 1));
    const caught = await catchFetchDidLog();
    expect(caught).toBeInstanceOf(VericertsError);
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
  });

  it('content-length が上限超過を宣言する応答は本文を読む前に 2003 で拒否する', async () => {
    mockResponse('short', {
      headers: { 'content-length': String(MAX_DOCUMENT_BYTES + 1) },
    });
    const caught = await catchFetchDidLog();
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
  });

  it('ちょうど MAX_DOCUMENT_BYTES の本文は受理する', async () => {
    mockResponse('a'.repeat(MAX_DOCUMENT_BYTES));
    expect((await fetchDidLog(LOG_URL)).length).toBe(MAX_DOCUMENT_BYTES);
  });
});

describe('fetchDidLog の最終 URL 判定', () => {
  it('ホストを持たない `https://` への追従は 2003 で拒否する', async () => {
    // `startsWith('https://')` は通してしまう値。判定を `isHttpsUrl` に寄せたことの回帰。
    mockResponse('{"versionId":"1"}\n', undefined, 'https://');
    const caught = await catchFetchDidLog();
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
  });

  it('平文へのリダイレクトは 2003 で拒否する', async () => {
    mockResponse('{"versionId":"1"}\n', undefined, 'http://evil.example/did.jsonl');
    const caught = await catchFetchDidLog();
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
  });
});

describe('fetchDidLog の Content-Type 検査', () => {
  it('`application/jsonl` の応答は受理する', async () => {
    mockResponse('{"versionId":"1"}\n', { headers: { 'content-type': 'application/jsonl' } });
    expect(await fetchDidLog(LOG_URL)).toBe('{"versionId":"1"}\n');
  });

  it('`text/html` のエラーページは行パーサへ渡さず 2003 で拒否する', async () => {
    mockResponse('<html>404</html>', { headers: { 'content-type': 'text/html; charset=utf-8' } });
    const caught = await catchFetchDidLog();
    expect(caught).toBeInstanceOf(VericertsError);
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
  });

  it('Content-Type 未設定の応答は 2003 で拒否する', async () => {
    // `Response` が本文から補う既定値を上書きするため、ヘッダを明示的に取り除く。
    globalThis.fetch = (async () => {
      const response = new Response('{"versionId":"1"}\n', { status: 200 });
      response.headers.delete('content-type');
      return response;
    }) as unknown as typeof fetch;
    const caught = await catchFetchDidLog();
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
  });

  it('受理する media type を `Accept` ヘッダで要求する', async () => {
    let accept: string | undefined;
    globalThis.fetch = (async (_url: string, init?: RequestInit) => {
      accept = (init?.headers as Record<string, string> | undefined)?.Accept;
      return new Response('{"versionId":"1"}\n', {
        status: 200,
        headers: { 'content-type': 'application/jsonl' },
      });
    }) as unknown as typeof fetch;
    await fetchDidLog(LOG_URL);
    expect(accept).toBe('text/jsonl, application/jsonl, text/plain');
  });
});

describe('fetchDidLog の fetch DI seam', () => {
  it('注入した `fetchFn` を使い、グローバル `fetch` を呼ばない', async () => {
    globalThis.fetch = (() => {
      throw new Error('global fetch must not be used');
    }) as unknown as typeof fetch;
    let injectedUrl: string | undefined;
    const injected = (async (url: string) => {
      injectedUrl = url;
      return new Response('{"versionId":"1"}\n', {
        status: 200,
        headers: { 'content-type': 'application/jsonl' },
      });
    }) as unknown as typeof fetch;
    expect(await fetchDidLog(LOG_URL, injected)).toBe('{"versionId":"1"}\n');
    expect(injectedUrl).toBe(LOG_URL);
  });
});
