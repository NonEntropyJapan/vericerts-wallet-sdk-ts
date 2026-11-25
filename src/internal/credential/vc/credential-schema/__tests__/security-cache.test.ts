/**
 * `validateCredentialSchema` のセキュリティ特性とキャッシュ。
 *
 * - リモート `$ref` は**取得せず**違反として報告する（SSRF 防止）。
 * - スキーマ文書は URL 完全一致キーで TTL 5 分キャッシュする。
 * - キャッシュはエントリ数に上限を持ち、超過分を古い順に追い出す（Issuer 制御 URL による DoS 防止）。
 * - 例外・違反メッセージに URL / `credentialSubject` の値を含めない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../../errors.js';
import { CredentialSchemaCache } from '../cache.js';
import { CREDENTIAL_SCHEMA_CACHE_TTL_MS } from '../types.js';
import { validateCredentialSchema } from '../validate.js';
import {
  buildVc,
  CLAIM_TOKEN,
  createFetchStub,
  PERSON_SCHEMA,
  SCHEMA_URL,
  URL_TOKEN,
} from './fixtures.js';

const EVIL_REF = 'https://evil.example/x.json';

describe('validateCredentialSchema — リモート $ref を取得しない', () => {
  it('リモート $ref は違反として報告し、その URL へは fetch しない', async () => {
    const stub = createFetchStub({
      [SCHEMA_URL]: {
        json: {
          type: 'object',
          required: ['name'],
          properties: { name: { $ref: EVIL_REF } },
        },
      },
      // 万一取得しに行った場合に成功してしまわないよう、あえて有効な応答も用意しておく。
      [EVIL_REF]: { json: { type: 'string' } },
    });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: new CredentialSchemaCache(),
      nowMs: 1000,
    });

    expect(result.valid).toBe(false);
    expect((result.errors ?? []).length).toBeGreaterThan(0);
    // スキーマ本体の 1 回だけ。リモート $ref の URL は一度も要求されていない。
    expect(stub.requested).toEqual([SCHEMA_URL]);
    expect(stub.requested).not.toContain(EVIL_REF);
  });

  it('ローカル JSON Pointer の $ref は解決して検証に使う', async () => {
    const stub = createFetchStub({
      [SCHEMA_URL]: {
        json: {
          type: 'object',
          required: ['name'],
          properties: { name: { $ref: '#/$defs/nonEmptyString' } },
          $defs: { nonEmptyString: { type: 'string', minLength: 1 } },
        },
      },
    });
    const vc = buildVc({ name: '' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: new CredentialSchemaCache(),
      nowMs: 1000,
    });

    // minLength 1 に違反するので、ローカル $ref が実際に解決されたことが分かる。
    expect(result.valid).toBe(false);
    expect(stub.requested).toEqual([SCHEMA_URL]);
  });
});

describe('validateCredentialSchema — TTL キャッシュ', () => {
  it('同一 URL の 2 回目はキャッシュを使い fetch は 1 回だけ', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const cache = new CredentialSchemaCache();
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });
    const options = { fetchImpl: stub.fetchImpl, schemaCache: cache, nowMs: 1000 };

    await validateCredentialSchema(vc, undefined, options);
    await validateCredentialSchema(vc, undefined, options);

    expect(stub.requested).toEqual([SCHEMA_URL]);
  });

  it('TTL（5 分）経過後は再取得する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const cache = new CredentialSchemaCache();
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: cache,
      nowMs: 1000,
    });
    await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: cache,
      nowMs: 1000 + CREDENTIAL_SCHEMA_CACHE_TTL_MS,
    });

    expect(stub.requested).toEqual([SCHEMA_URL, SCHEMA_URL]);
  });

  it('別 URL は別エントリとして扱う（キーは URL 完全一致）', async () => {
    const otherUrl = `${SCHEMA_URL}?v=2`;
    const stub = createFetchStub({
      [SCHEMA_URL]: { json: PERSON_SCHEMA },
      [otherUrl]: { json: PERSON_SCHEMA },
    });
    const cache = new CredentialSchemaCache();
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: cache,
      nowMs: 1000,
    });
    await validateCredentialSchema(vc, otherUrl, {
      fetchImpl: stub.fetchImpl,
      schemaCache: cache,
      nowMs: 1000,
    });

    expect(stub.requested).toEqual([SCHEMA_URL, otherUrl]);
  });
});

describe('CredentialSchemaCache — エントリ数の上限', () => {
  it('上限を超えたら古いエントリから追い出す（無制限に積み上げない）', () => {
    // スキーマ URL は Issuer 制御下にあるため、上限が無いと毎回異なる URL の VC を流すだけで
    // 1 エントリ最大 1 MiB が際限なく積み上がる。
    const cache = new CredentialSchemaCache(60_000, 2);

    cache.set('https://a.example.com/s.json', { type: 'object' }, 0);
    cache.set('https://b.example.com/s.json', { type: 'string' }, 0);
    cache.set('https://c.example.com/s.json', { type: 'number' }, 0);

    expect(cache.get('https://a.example.com/s.json', 0)).toBeUndefined();
    expect(cache.get('https://b.example.com/s.json', 0)).toEqual({ type: 'string' });
    expect(cache.get('https://c.example.com/s.json', 0)).toEqual({ type: 'number' });
  });

  it('同一キーの上書きはエントリ数を増やさない', () => {
    const cache = new CredentialSchemaCache(60_000, 2);

    cache.set('https://a.example.com/s.json', { type: 'object' }, 0);
    cache.set('https://a.example.com/s.json', { type: 'string' }, 0);
    cache.set('https://b.example.com/s.json', { type: 'number' }, 0);

    expect(cache.get('https://a.example.com/s.json', 0)).toEqual({ type: 'string' });
    expect(cache.get('https://b.example.com/s.json', 0)).toEqual({ type: 'number' });
  });
});

describe('validateCredentialSchema — 秘密を漏らさない', () => {
  it('取得失敗の例外に URL を含めない', async () => {
    const leakyUrl = `https://issuer.example.com/schemas/${URL_TOKEN}.json`;
    const stub = createFetchStub({ [leakyUrl]: { networkError: true } });
    const vc = buildVc({ name: '山田太郎' }, { id: leakyUrl, type: 'JsonSchema' });

    let caught: VericertsError | undefined;
    try {
      await validateCredentialSchema(vc, undefined, {
        fetchImpl: stub.fetchImpl,
        schemaCache: new CredentialSchemaCache(),
        nowMs: 1000,
      });
    } catch (err) {
      caught = err as VericertsError;
    }

    expect(caught?.code).toBe(ErrorCodes.SCHEMA_FETCH_FAILED);
    expect(caught?.message).not.toContain(URL_TOKEN);
    expect(JSON.stringify(caught?.context ?? {})).not.toContain(URL_TOKEN);
    expect(caught?.cause).toBeUndefined();
  });

  it('違反メッセージに credentialSubject の値を含めない', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    // nickname は maxLength 8。違反値にトークンを埋め込む。
    const vc = buildVc(
      { name: '山田太郎', nickname: CLAIM_TOKEN },
      { id: SCHEMA_URL, type: 'JsonSchema' },
    );

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: new CredentialSchemaCache(),
      nowMs: 1000,
    });

    expect(result.valid).toBe(false);
    const serialized = JSON.stringify(result.errors ?? []);
    expect(serialized).not.toContain(CLAIM_TOKEN);
    for (const error of result.errors ?? []) {
      expect(error.message).not.toContain(CLAIM_TOKEN);
    }
  });
});
