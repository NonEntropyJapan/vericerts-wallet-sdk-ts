/**
 * well-known Metadata 文書取得の共通トランスポート（`internal/auth/well-known-json/index.ts`）。
 *
 * Issuer Metadata と AS Metadata の取得を検証する。
 *
 * 本モジュールは Issuer Metadata と AS Metadata の**両方**の入口検査を 1 か所で持つ。したがって
 * 検査の分岐は呼び出し側（`eudi/issuance/metadata.ts` / `oid4vci-as-metadata.ts`）ごとのテストに
 * 頼らず、ここで直接固定する。とくに「**タイムアウトは本文読了までを 1 つの `AbortController` で
 * 覆う**」という宣言は、本文ストリームの失敗を `fetch_failed` へ落とす経路が唯一の観測点である。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../errors.js';
import {
  fetchJson,
  ISSUER,
  json,
  METADATA_URL,
  stubFetch,
  WELL_KNOWN_PATH,
} from '../well-known-json/__tests__/fixtures.js';

describe('fetchWellKnownJson の正常系', () => {
  test('well-known URL を GET し、プロトタイプを外した文書を返す', async () => {
    const stub = stubFetch(() => json({ credential_issuer: ISSUER }));
    const parsed = await fetchJson(ISSUER, stub.fetchImpl);
    expect(stub.urls).toEqual([METADATA_URL]);
    // `parseJsonWithoutPrototype` を通すので、返る文書は `Object.prototype` を継承しない。
    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(Object.hasOwn(parsed, 'credential_issuer')).toBe(true);
  });

  test('末尾スラッシュのある識別子でも `//.well-known` にならない', async () => {
    const stub = stubFetch(() => json({}));
    await fetchJson(`${ISSUER}//`, stub.fetchImpl);
    expect(stub.urls).toEqual([METADATA_URL]);
  });
});

describe('fetchWellKnownJson の入口検査', () => {
  test('非 HTTPS の識別子は fetch を 1 度も発生させずに拒否する', async () => {
    const stub = stubFetch(() => json({}));
    await expect(fetchJson('http://issuer.example.eu', stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'non_https_issuer' },
    });
    // SSRF / 平文降格を防ぐため、判定は取得より前に行う。
    expect(stub.urls).toEqual([]);
  });

  test('URL として成立しない識別子も non_https_issuer で拒否する', async () => {
    const stub = stubFetch(() => json({}));
    await expect(fetchJson('not a url', stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'non_https_issuer' },
    });
    expect(stub.urls).toEqual([]);
  });

  test('fetch の失敗は fetch_failed へ正規化する（URL・cause を漏らさない）', async () => {
    const error = await fetchJson(ISSUER, () => Promise.reject(new Error('boom'))).catch(
      (e: unknown) => e,
    );
    expect(error).toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
      context: { reason: 'fetch_failed' },
    });
    expect((error as { cause?: unknown }).cause).toBeUndefined();
  });

  test('リダイレクトで HTTP へ降格した応答は insecure_redirect で拒否する', async () => {
    // 構築した `Response` の `url` は空文字なので、最終 URL を明示して降格を再現する。
    const downgraded = json({});
    Object.defineProperty(downgraded, 'url', {
      value: `http://issuer.example.eu${WELL_KNOWN_PATH}`,
    });
    await expect(fetchJson(ISSUER, () => Promise.resolve(downgraded))).rejects.toMatchObject({
      context: { reason: 'insecure_redirect' },
    });
  });

  test('非 2xx は http_error で拒否する', async () => {
    const stub = stubFetch(() => json({}, 500));
    await expect(fetchJson(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'http_error' },
    });
  });

  test('本文の読み出しが失敗したら fetch_failed（タイムアウトが本文読了まで覆う証跡）', async () => {
    // ヘッダだけ 200 を返して本文ストリームを error させる。`response.text()` が reject する
    // この経路が、abort シグナルを本文読了まで持たせている唯一の観測点である。
    const streaming = (): Response =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error('stream aborted'));
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    await expect(fetchJson(ISSUER, () => Promise.resolve(streaming()))).rejects.toMatchObject({
      context: { reason: 'fetch_failed' },
    });
  });

  test('JSON でない本文は invalid_json で拒否する', async () => {
    const stub = stubFetch(
      () =>
        new Response('not json', {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    );
    await expect(fetchJson(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'invalid_json' },
    });
  });

  test('配列の本文は invalid_metadata で拒否する', async () => {
    const stub = stubFetch(() => json([]));
    await expect(fetchJson(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'invalid_metadata' },
    });
  });

  test('null の本文も invalid_metadata で拒否する（typeof null === "object"）', async () => {
    const stub = stubFetch(() => json(null));
    await expect(fetchJson(ISSUER, stub.fetchImpl)).rejects.toMatchObject({
      context: { reason: 'invalid_metadata' },
    });
  });
});

describe('fetchWellKnownJson の DI 解決', () => {
  test('Object.prototype.fetchImpl の汚染値を掴まない', async () => {
    const polluted: string[] = [];
    (Object.prototype as unknown as Record<string, unknown>).fetchImpl = (url: string) => {
      polluted.push(url);
      return Promise.resolve(json({ credential_issuer: ISSUER }));
    };
    try {
      const stub = stubFetch(() => json({ credential_issuer: ISSUER }));
      await fetchJson(ISSUER, stub.fetchImpl);
      // 明示注入が優先され、汚染値は 1 度も呼ばれない。
      expect(stub.urls).toEqual([METADATA_URL]);
      expect(polluted).toEqual([]);
    } finally {
      // 他テストへ漏らさないため必ず消す。
      delete (Object.prototype as unknown as Record<string, unknown>).fetchImpl;
    }
  });
});
