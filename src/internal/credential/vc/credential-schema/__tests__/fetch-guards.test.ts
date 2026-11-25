/**
 * スキーマ文書取得のハードニング。
 *
 * 共有プリミティブ（`internal/http/fetch-json.ts` を `json-schema/fetch-document.ts` が正規化する）
 * の防御が `validateCredentialSchema` 経由でも効いていることを確認する: HTTPS 限定・リダイレクト後も
 * HTTPS・JSON Content-Type 必須・非 2xx 拒否・本文 1 MiB 上限・タイムアウト。いずれも 3015 に
 * 正規化され、`reason` は well-known Metadata 取得と同じ固定識別子を使う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { MAX_SCHEMA_DOCUMENT_BYTES } from '../../../json-schema/index.js';
import { CredentialSchemaCache } from '../cache.js';
import { validateCredentialSchema } from '../validate.js';
import {
  buildVc,
  createFetchStub,
  PERSON_SCHEMA,
  SCHEMA_URL,
  type StubResponse,
} from './fixtures.js';

/** 指定 URL のスキーマを引く VC を、指定の応答スタブで検証したときの拒否理由を取り出す。 */
async function expectFetchRejection(
  url: string,
  route: StubResponse | undefined,
): Promise<{ error: VericertsError; requested: string[] }> {
  const stub = createFetchStub(route === undefined ? {} : { [url]: route });
  const vc = buildVc({ name: '山田太郎' }, { id: url, type: 'JsonSchema' });
  try {
    await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: new CredentialSchemaCache(),
      nowMs: 1000,
    });
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    const error = err as VericertsError;
    expect(error.code).toBe(ErrorCodes.SCHEMA_FETCH_FAILED);
    return { error, requested: stub.requested };
  }
  throw new Error('3015 が投げられませんでした');
}

describe('validateCredentialSchema — 非 HTTPS URL は取得しない', () => {
  it.each([
    ['http', 'http://issuer.example.com/schemas/person.json'],
    ['file', 'file:///etc/passwd'],
    ['data', 'data:application/json,{"type":"object"}'],
  ])('%s スキームは 3015 で拒否し fetch を呼ばない', async (_label, url) => {
    const { error, requested } = await expectFetchRejection(url, undefined);
    expect(error.context).toEqual({ reason: 'non_https_url' });
    expect(requested).toEqual([]);
  });
});

describe('validateCredentialSchema — 応答の検証', () => {
  it('リダイレクトで http へ降格した応答を 3015 で拒否する', async () => {
    const { error } = await expectFetchRejection(SCHEMA_URL, {
      json: PERSON_SCHEMA,
      finalUrl: 'http://downgraded.example.com/schemas/person.json',
    });
    expect(error.context).toEqual({ reason: 'insecure_redirect' });
  });

  it('非 2xx 応答を 3015 で拒否する', async () => {
    const { error, requested } = await expectFetchRejection(SCHEMA_URL, {
      json: PERSON_SCHEMA,
      status: 404,
    });
    expect(requested).toEqual([SCHEMA_URL]);
    expect(error.code).toBe(ErrorCodes.SCHEMA_FETCH_FAILED);
  });

  it('JSON でない Content-Type を 3015 で拒否する', async () => {
    const { error } = await expectFetchRejection(SCHEMA_URL, {
      json: PERSON_SCHEMA,
      contentType: 'text/html; charset=utf-8',
    });
    expect(error.context).toEqual({ reason: 'invalid_content_type' });
  });

  it('JSON としてパースできない本文を 3015 で拒否する', async () => {
    const { error } = await expectFetchRejection(SCHEMA_URL, { body: 'not json at all' });
    expect(error.context).toEqual({ reason: 'invalid_json' });
  });

  it('JSON object でない本文（配列）を 3015 で拒否する', async () => {
    const { error } = await expectFetchRejection(SCHEMA_URL, { json: [1, 2, 3] });
    expect(error.context).toEqual({ reason: 'invalid_metadata' });
  });

  it('ネットワークエラー / タイムアウト（abort）を 3015 に正規化する', async () => {
    const { error } = await expectFetchRejection(SCHEMA_URL, { abortError: true });
    // abort 由来でも URL・原因は漏らさない（`reason` は固定識別子だけ）。
    expect(error.context).toEqual({ reason: 'fetch_failed' });
  });
});

describe('validateCredentialSchema — 本文サイズ上限（1 MiB）', () => {
  it('content-length が上限超過を宣言していれば本文を読まずに 3015 で拒否する', async () => {
    const { error } = await expectFetchRejection(SCHEMA_URL, {
      json: PERSON_SCHEMA,
      contentLength: String(MAX_SCHEMA_DOCUMENT_BYTES + 1),
    });
    expect(error.context).toEqual({ reason: 'oversized_body' });
  });

  it('content-length が無くても実バイト数が上限を超えたら 3015 で拒否する', async () => {
    // 64 KiB × 17 = 1.06 MiB。ReadableStream 応答には content-length が付かないため、
    // ストリーム読み出し中の累積バイト数で打ち切れることを確認する。
    const chunk = 'a'.repeat(64 * 1024);
    const chunks = Array.from({ length: 17 }, () => chunk);
    expect(chunks.length * chunk.length).toBeGreaterThan(MAX_SCHEMA_DOCUMENT_BYTES);

    const { error } = await expectFetchRejection(SCHEMA_URL, { chunks });
    expect(error.context).toEqual({ reason: 'oversized_body' });
  });

  it('上限ちょうどまでの本文は受理する', async () => {
    // `{"type":"object","properties":{"name":{"type":"string"},"pad":{"description":"..."}}}`
    // を 1 MiB 未満に収めたスキーマ。パディングを含めても読み切れることを確認する。
    const padding = 'p'.repeat(MAX_SCHEMA_DOCUMENT_BYTES - 4096);
    const stub = createFetchStub({
      [SCHEMA_URL]: {
        json: { type: 'object', required: ['name'], $comment: padding },
      },
    });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: new CredentialSchemaCache(),
      nowMs: 1000,
    });

    expect(result.valid).toBe(true);
  });
});
