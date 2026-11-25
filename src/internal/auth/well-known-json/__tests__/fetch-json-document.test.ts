/**
 * `fetchJsonDocument` の本文取得規律 — **サイズ上限 / Content-Type / 最終 URL の束縛**。
 *
 * JWT VC Issuer Metadata 経路を検証する。
 *
 * この経路には受領した VC 由来（= 攻撃者が影響し得る）の `iss` / `jwks_uri` が流れる。同種の
 * Issuer 由来取得（`credential/json-schema/fetch-document.ts` / Extension の status-list）に既に
 * 確立している規律 —— 1 MiB 上限 + `content-length` の事前拒否 + JSON Content-Type 必須 ——
 * がこの入口にも効いていることと、`expectedOrigin` を渡したときに**リダイレクト後の最終 URL**まで
 * origin を突き合わせることを固定する。入口検査そのもの（HTTPS / http_error / invalid_json /
 * invalid_metadata）は `internal/auth/__tests__/well-known-json.test.ts` が持つ。
 *
 * 識別子・失敗ファクトリ・fetch スタブは `./fixtures.ts` と共有する。
 */

import { describe, expect, test } from 'bun:test';
import type { FetchLike } from '../../../fetch-di.js';
import { MAX_DOCUMENT_BYTES } from '../../../http/body-limit.js';
import { fetchJsonDocument } from '../index.js';
import { failure, fetchJson, ISSUER, METADATA_URL, stubFetch } from './fixtures.js';

/** JSON 本文と任意のヘッダ / 最終 URL を持つ 200 応答。 */
function response(body: string, headers: Record<string, string>, finalUrl?: string): Response {
  const res = new Response(body, { status: 200, headers });
  if (finalUrl === undefined) {
    return res;
  }
  // `Response.url` は読み取り専用なので、リダイレクト後の最終 URL は定義し直して模す。
  Object.defineProperty(res, 'url', { value: finalUrl });
  return res;
}

describe('fetchJsonDocument の本文取得規律', () => {
  test('JSON でない Content-Type は本文を読まずに invalid_content_type で拒否する', async () => {
    // 「JSON に見える別物」を掴まないための入口検査。本文が正しい JSON でも種別で落とす。
    const stub = stubFetch(() =>
      response(JSON.stringify({ issuer: ISSUER }), { 'Content-Type': 'text/html' }),
    );
    await expect(fetchJson(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'invalid_content_type' },
    });
  });

  test('`application/jwk-set+json` のような `+json` 系 Content-Type は受理する', async () => {
    const stub = stubFetch(() =>
      response(JSON.stringify({ issuer: ISSUER }), {
        'Content-Type': 'application/jwk-set+json; charset=utf-8',
      }),
    );
    await expect(fetchJson(ISSUER, stub.fetchImpl)).resolves.toMatchObject({ issuer: ISSUER });
  });

  test('`content-length` が上限超を宣言したら本文を読まずに oversized_body で拒否する', async () => {
    // 本文自体は小さいので、落ちるのは自己申告の `content-length` を見た時点（読む前）である。
    const stub = stubFetch(() =>
      response(JSON.stringify({ issuer: ISSUER }), {
        'Content-Type': 'application/json',
        'Content-Length': String(MAX_DOCUMENT_BYTES + 1),
      }),
    );
    await expect(fetchJson(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'oversized_body' },
    });
  });

  test('`content-length` を偽っても実バイト数が上限を超えれば oversized_body で拒否する', async () => {
    // 上限が自己申告ではなく実バイト数でも効くこと（ストリームを途中で cancel する経路）。
    const padding = 'a'.repeat(MAX_DOCUMENT_BYTES);
    const stub = stubFetch(() =>
      response(`{"pad":"${padding}"}`, {
        'Content-Type': 'application/json',
        'Content-Length': '10',
      }),
    );
    await expect(fetchJson(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'oversized_body' },
    });
  });
});

describe('fetchJsonDocument の最終 URL 束縛', () => {
  const ORIGIN = new URL(ISSUER).origin;

  /** `expectedOrigin` 付きで直接叩く（`jwks_uri` 取得と同じ呼び方）。 */
  function fetchBound(fetchImpl: FetchLike): Promise<object> {
    return fetchJsonDocument(METADATA_URL, fetchImpl, failure, ORIGIN);
  }

  test('別 origin へリダイレクトした応答は cross_origin_redirect で拒否する', async () => {
    // 取得前の URL だけを縛っても、同一 origin の URL が別 origin へ 302 すれば追随してしまい、
    // origin 束縛（`jwks_uri` の「`iss` と同一 origin」など）が実効を持たない。
    const stub = stubFetch(() =>
      response(
        JSON.stringify({ keys: [] }),
        { 'Content-Type': 'application/json' },
        'https://attacker.example/keys',
      ),
    );
    await expect(fetchBound(stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'cross_origin_redirect' },
    });
  });

  test('同一 origin 内のリダイレクトは受理する', async () => {
    const stub = stubFetch(() =>
      response(
        JSON.stringify({ keys: [] }),
        { 'Content-Type': 'application/json' },
        `${ISSUER}/moved/keys`,
      ),
    );
    await expect(fetchBound(stub.fetchImpl)).resolves.toMatchObject({ keys: [] });
  });

  test('`response.url` を持たない応答でも origin 束縛は課す', async () => {
    // 公開 DI（`createWallet({ eudiFetchImpl })`）の実装が `new Response(await r.text(), …)` で
    // 応答を組み直すと `response.url` は空文字になる。そこで束縛ごと無効化すると、
    // `jwt-vc-issuer.ts` がセキュリティ制御として渡している origin 束縛が、正当な DI を
    // 挟むだけで消える。束縛そのものは実際に辿った最終 URL で課す（次のテスト）。
    const stub = stubFetch(() =>
      response(JSON.stringify({ keys: [] }), { 'Content-Type': 'application/json' }),
    );
    expect(new Response('{}').url).toBe('');

    // 束縛内: リクエスト URL の origin と一致するので受理する。
    await expect(fetchBound(stub.fetchImpl)).resolves.toMatchObject({ keys: [] });

    // 束縛外: `jwks_uri` が別 origin を指していれば、`response.url` が無くても拒否する。
    await expect(
      fetchJsonDocument('https://attacker.example/keys', stub.fetchImpl, failure, ORIGIN),
    ).rejects.toMatchObject({ context: { reason: 'cross_origin_redirect' } });
  });

  test('`response.url` を持たない DI fetch でも、別 origin への 302 は cross_origin_redirect で拒否する', async () => {
    // 同一 origin の URL → 別 origin へ 302。応答（200）は `url` が空のため、リクエスト URL
    // だけを検査していると別 origin の応答を受理してしまう。
    const seen: string[] = [];
    const fetchImpl: FetchLike = async (url) => {
      seen.push(url);
      return url.startsWith(`${ISSUER}/`)
        ? new Response(null, {
            status: 302,
            headers: { location: 'https://attacker.example/jwks.json' },
          })
        : new Response('{"keys":[]}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
    };
    await expect(fetchBound(fetchImpl)).rejects.toMatchObject({
      context: { reason: 'cross_origin_redirect' },
    });
    expect(seen).toEqual([METADATA_URL, 'https://attacker.example/jwks.json']);
  });

  test('HTTP へ降格したリダイレクトは origin 束縛より先に insecure_redirect で落ちる', async () => {
    const stub = stubFetch(() =>
      response(
        JSON.stringify({ keys: [] }),
        { 'Content-Type': 'application/json' },
        'http://issuer.example.eu/keys',
      ),
    );
    await expect(fetchBound(stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'insecure_redirect' },
    });
  });
});
