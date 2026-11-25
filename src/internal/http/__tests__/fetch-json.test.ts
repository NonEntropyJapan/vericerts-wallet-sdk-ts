/**
 * 共有トランスポート `fetchJsonWithinLimits` の**リクエスト側**の規律。
 *
 * 応答側の検査（Content-Type / サイズ上限 / 最終 URL の束縛 / パース）は
 * `auth/well-known-json/__tests__/fetch-json-document.test.ts` と
 * `credential/vc/credential-schema/__tests__/fetch-guards.test.ts` が持つ。ここで固定するのは
 * 「どんな init で `fetch` を呼ぶか」だけである。
 *
 * **なぜ init を直接見るのか。** GET に body を付けると Node/undici とブラウザは `Request` 構築の
 * 時点で `TypeError: Request with GET/HEAD method cannot have body.` を投げる（空文字でも例外）。
 * SDK のビルド target は browser なので、これは `fetchImpl` を注入しない本番経路が**1 度も
 * ネットワークへ到達しない**ことを意味する。ところが Bun の `fetch` / `Request` だけはこれを
 * 許容するため、スタブを注入するテストでは緑のまま通ってしまう。そこで規則そのものを
 * {@link assertGetHasNoBody} として明文化し、Bun 上でも落ちる形で課す。
 */

import { describe, expect, test } from 'bun:test';
import type { FetchLike } from '../../fetch-di.js';
import { MAX_DOCUMENT_BYTES } from '../body-limit.js';
import { fetchJsonWithinLimits } from '../fetch-json.js';

const URL_UNDER_TEST = 'https://issuer.example.com/schemas/person.json';

/** 取得失敗を素の `Error` へ正規化する（コードの選択は本テストの関心事ではない）。 */
function failure(reason: string): Error {
  return new Error(reason);
}

/** JSON を返す 200 応答（`url` は既定で取得先そのもの）。 */
function jsonResponse(body: string, url: string = URL_UNDER_TEST): Response {
  const res = new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
  Object.defineProperty(res, 'url', { value: url });
  return res;
}

/** 指定の最終 URL を持つ 200 応答を返す `fetchImpl`。 */
function respondingWithFinalUrl(finalUrl: string): FetchLike {
  return () => Promise.resolve(jsonResponse('{"ok":true}', finalUrl));
}

/**
 * WHATWG Fetch の「GET/HEAD のリクエストは body を持てない」規則を、その規則を強制しない
 * ランタイム（Bun）でも同じように課す。
 *
 * 規則は `Request` のコンストラクタ（https://fetch.spec.whatwg.org/#dom-request）にあり、
 * 「init["body"] が存在して非 null かつ method が GET / HEAD なら TypeError」である。
 * `body: ''` は「存在して非 null」なので例外になる — 空文字なら送信されないから安全、では**ない**。
 */
function assertGetHasNoBody(url: string, init: Record<string, unknown>): void {
  const body = init.body;
  if ((init.method === 'GET' || init.method === 'HEAD') && body !== undefined && body !== null) {
    throw new TypeError('Request with GET/HEAD method cannot have body.');
  }
  // 規則を通った init が実際に `Request` として組めることも確かめる（Bun でも通る形）。
  new Request(url, init as RequestInit);
}

describe('fetchJsonWithinLimits が組み立てる GET リクエスト', () => {
  test('init に body を載せない（実 fetch は GET+body を TypeError にする）', async () => {
    let seen: Record<string, unknown> | undefined;
    const fetchImpl: FetchLike = (url, init) => {
      seen = init as unknown as Record<string, unknown>;
      assertGetHasNoBody(url, seen);
      return Promise.resolve(jsonResponse('{"type":"object"}'));
    };

    const document = await fetchJsonWithinLimits(URL_UNDER_TEST, fetchImpl, failure);

    expect(document).toEqual({ type: 'object' });
    // `body: undefined` を載せるのではなく、キーごと生やさないことまで固定する。
    expect(Object.hasOwn(seen as object, 'body')).toBe(false);
  });

  test('GET / Accept ヘッダ / abort シグナルは載せる', async () => {
    let seen: Record<string, unknown> | undefined;
    const fetchImpl: FetchLike = (_url, init) => {
      seen = init as unknown as Record<string, unknown>;
      return Promise.resolve(jsonResponse('{}'));
    };

    await fetchJsonWithinLimits(URL_UNDER_TEST, fetchImpl, failure);

    expect(seen?.method).toBe('GET');
    expect(seen?.headers).toEqual({ Accept: 'application/json' });
    expect(seen?.signal).toBeInstanceOf(AbortSignal);
  });

  test('`assertGetHasNoBody` は GET + 空文字 body を TypeError にする（ガード自身の回帰）', () => {
    // このガードが素通りだと上のテストが空虚になるため、ガード自体も固定する。
    expect(() =>
      assertGetHasNoBody(URL_UNDER_TEST, { method: 'GET', headers: {}, body: '' }),
    ).toThrow(TypeError);
  });
});

describe('fetchJsonWithinLimits の最終 URL 検査', () => {
  // HTTPS 判定は共有ヘルパー `isHttpsUrl`（`new URL` + `protocol === 'https:'`）に寄せる。
  // ここだけ `startsWith('https://')` で書くと、同じファイルの取得前検査
  // （`fetchJsonWithinLimits` 冒頭の `isHttpsUrl`）と条件がずれ、「一方の経路だけ非 HTTPS を
  // 通す」状態になる（`https-url.ts` の docblock が禁じている）。
  test('ホストを持たない `https://` は最終 URL として拒否する', async () => {
    await expect(
      fetchJsonWithinLimits(URL_UNDER_TEST, respondingWithFinalUrl('https://'), failure),
    ).rejects.toThrow('insecure_redirect');
  });

  test('平文へ降格した最終 URL は拒否する', async () => {
    await expect(
      fetchJsonWithinLimits(
        URL_UNDER_TEST,
        respondingWithFinalUrl('http://issuer.example.com/schemas/person.json'),
        failure,
      ),
    ).rejects.toThrow('insecure_redirect');
  });

  test('HTTPS を保った最終 URL は通す', async () => {
    const document = await fetchJsonWithinLimits(
      URL_UNDER_TEST,
      respondingWithFinalUrl('https://issuer.example.com/schemas/person-v2.json'),
      failure,
    );
    expect(document).toEqual({ ok: true });
  });
});

/**
 * 本文を読まずに失敗へ倒す経路が、応答本体を解放して（`cancel()`）から throw することの規律。
 *
 * 未消費の本文は undici でもブラウザでも接続とバッファ済みバイトを GC まで保持する。本関数は
 * 約 14 の取得経路が通る共有トランスポートなので、ここでの 1 件の取りこぼしがそのまま 14 経路の
 * 接続リークになる。`cancel()` の回数を記録するストリームダブルで、読み出し前 throw の各経路が
 * ちょうど 1 度解放することを固定する。
 */
describe('本文を読まずに失敗する経路の後始末', () => {
  /** `cancel()` を記録するストリームを本文に持つ応答ダブル。 */
  function recordingResponse(init: { status?: number; headers: Record<string, string> }): {
    response: Response;
    cancelCount: () => number;
  } {
    let cancelCount = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new TextEncoder().encode('{"ok":true}'));
        controller.close();
      },
      cancel() {
        cancelCount += 1;
      },
    });
    const response = {
      body,
      ok: (init.status ?? 200) < 400,
      status: init.status ?? 200,
      url: URL_UNDER_TEST,
      headers: new Headers(init.headers),
    } as unknown as Response;
    return { response, cancelCount: () => cancelCount };
  }

  test.each([
    ['非 2xx 応答', { status: 500, headers: { 'Content-Type': 'application/json' } }],
    ['Content-Type が JSON でない', { headers: { 'Content-Type': 'text/html' } }],
    [
      '宣言サイズが上限超過',
      {
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(MAX_DOCUMENT_BYTES + 1),
        },
      },
    ],
  ] as ReadonlyArray<
    readonly [string, { status?: number; headers: Record<string, string> }]
  >)('%s は本体を解放してから失敗する', async (_label, init) => {
    const { response, cancelCount } = recordingResponse(init);
    await expect(
      fetchJsonWithinLimits(URL_UNDER_TEST, () => Promise.resolve(response), failure),
    ).rejects.toThrow();
    await Promise.resolve();
    expect(cancelCount()).toBe(1);
  });

  test('成功経路では本体を二重に解放しない', async () => {
    const { response, cancelCount } = recordingResponse({
      headers: { 'Content-Type': 'application/json' },
    });
    expect(
      await fetchJsonWithinLimits(URL_UNDER_TEST, () => Promise.resolve(response), failure),
    ).toEqual({ ok: true });
    await Promise.resolve();
    expect(cancelCount()).toBe(0);
  });
});
