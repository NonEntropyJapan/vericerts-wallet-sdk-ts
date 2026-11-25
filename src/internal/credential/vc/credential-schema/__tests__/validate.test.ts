/**
 * `validateCredentialSchema` の基本動作。
 *
 * - `credentialSubject` を検証する（VC 全体ではない）。
 * - 必須 / 任意属性の違反を `required` フラグで区別する（FO-4）。
 * - スキーマ URL の解決順（明示引数 > `credentialSchema`）と 3016 の境界。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { CredentialSchemaCache } from '../cache.js';
import { validateCredentialSchema } from '../validate.js';
import {
  buildVc,
  createFetchStub,
  OVERRIDE_SCHEMA_URL,
  PERSON_SCHEMA,
  SCHEMA_URL,
} from './fixtures.js';

/** 既定キャッシュを共有しないよう、テストごとに専用キャッシュを渡す。 */
function freshCache(): CredentialSchemaCache {
  return new CredentialSchemaCache();
}

describe('validateCredentialSchema — 正常系', () => {
  it('スキーマに適合する credentialSubject は valid: true を返す', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const vc = buildVc(
      { name: '山田太郎', nickname: 'たろ' },
      { id: SCHEMA_URL, type: 'JsonSchema' },
    );

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result.valid).toBe(true);
    expect(result.errors).toBeUndefined();
    expect(stub.requested).toEqual([SCHEMA_URL]);
  });

  it('credentialSchema が配列でも JSON Schema 系の先頭エントリを使う', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const vc = buildVc({ name: '山田太郎' }, [
      { id: 'https://issuer.example.com/shacl.ttl', type: 'ShaclValidator2017' },
      { id: SCHEMA_URL, type: 'JsonSchema' },
      { id: OVERRIDE_SCHEMA_URL, type: 'JsonSchemaCredential' },
    ]);

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result.valid).toBe(true);
    expect(stub.requested).toEqual([SCHEMA_URL]);
  });

  it('VC 全体ではなく credentialSubject を検証する', async () => {
    // VC のトップレベル必須プロパティ（issuer 等）を要求するスキーマではなく、
    // クレーム側のプロパティを要求するスキーマが適用されることを確かめる。
    const subjectOnlySchema = { type: 'object', required: ['name'], properties: {} };
    const stub = createFetchStub({ [SCHEMA_URL]: { json: subjectOnlySchema } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result.valid).toBe(true);
  });
});

describe('validateCredentialSchema — 違反の分類', () => {
  it('必須属性の欠落は required: true の違反になる', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const vc = buildVc({ nickname: 'たろ' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result.valid).toBe(false);
    const errors = result.errors ?? [];
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some((e) => e.required)).toBe(true);
  });

  it('任意属性の違反は required: false の違反になる', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    // nickname は maxLength 8。必須の name は満たしたうえで任意側のみ違反させる。
    const vc = buildVc(
      { name: '山田太郎', nickname: 'ながすぎるニックネームです' },
      { id: SCHEMA_URL, type: 'JsonSchema' },
    );

    const result = await validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result.valid).toBe(false);
    const errors = result.errors ?? [];
    expect(errors.length).toBe(1);
    expect(errors[0]?.required).toBe(false);
    expect(errors[0]?.path).toBe('/nickname');
  });
});

describe('validateCredentialSchema — スキーマ URL の解決', () => {
  it('明示 schema 引数は credentialSchema より優先される', async () => {
    const strictSchema = { type: 'object', required: ['name', 'nickname'] };
    const stub = createFetchStub({
      [SCHEMA_URL]: { json: PERSON_SCHEMA },
      [OVERRIDE_SCHEMA_URL]: { json: strictSchema },
    });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const result = await validateCredentialSchema(vc, OVERRIDE_SCHEMA_URL, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    // 上書き側スキーマ（nickname 必須）で検証されるので違反になる。
    expect(result.valid).toBe(false);
    expect(stub.requested).toEqual([OVERRIDE_SCHEMA_URL]);
  });

  it('credentialSchema も schema 引数も無い場合は 3016 を投げる', async () => {
    const stub = createFetchStub({});
    const vc = buildVc({ name: '山田太郎' });

    const promise = validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_NOT_SPECIFIED });
    expect(stub.requested).toEqual([]);
  });

  it('JSON Schema 系でない type だけの credentialSchema は 3016 を投げる', async () => {
    const stub = createFetchStub({});
    const vc = buildVc(
      { name: '山田太郎' },
      {
        id: 'https://issuer.example.com/shacl.ttl',
        type: 'ShaclValidator2017',
      },
    );

    const promise = validateCredentialSchema(vc, undefined, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_NOT_SPECIFIED });
    expect(stub.requested).toEqual([]);
  });
});
