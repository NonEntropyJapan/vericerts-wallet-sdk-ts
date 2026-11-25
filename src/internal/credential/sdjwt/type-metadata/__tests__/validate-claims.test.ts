/**
 * Type Metadata によるクレーム構造検証のテスト。
 *
 * 検証内容:
 * - `schema`(インライン)と `schema_uri`(別取得)の双方でクレームを検証する。
 * - `extends` で継承したスキーマが子の検証に効く。
 * - **構造不正(3061)は fail-open しない**。override の指定によらず常に例外として伝播する
 *   (`vct` 不一致 = 型すり替えを黙って通さない)。
 * - `vct` が URL でない場合は Type Metadata が存在しないため検証をスキップする。
 * - `schema_uri` の取得結果もキャッシュされる。
 *
 * 必須 / 任意違反の区別(FO-4)と取得失敗時の fail-safe(FO-3、同意・監査ゲート回帰)は
 * `validate-claims-fail-safe.test.ts` が固定する(Linterly の 300 行上限のため分割)。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { TypeMetadataCache } from '../cache.js';
import { validateClaimsAgainstTypeMetadata } from '../resolve.js';
import type { SdJwtTypeMetadata } from '../types.js';
import {
  BASE_METADATA,
  BASE_VCT,
  CHILD_METADATA,
  CHILD_VCT,
  createFetchStub,
  SCHEMA_URI,
} from './fixtures.js';

/** 期待するエラーコードで reject されることを確認する。 */
async function expectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(code);
  }
}

/** テストごとに独立したキャッシュを使う。 */
function freshCaches() {
  return {
    metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
    schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
  };
}

describe('validateClaimsAgainstTypeMetadata — 適合判定', () => {
  it('インライン schema でクレームを検証する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎', nickname: 'たろ' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result).toEqual({ valid: true, schemaAvailable: true, warnings: [] });
  });

  it('schema_uri を取得してクレームを検証する', async () => {
    const stub = createFetchStub({
      [BASE_VCT]: { json: { vct: BASE_VCT, schema_uri: SCHEMA_URI } },
      [SCHEMA_URI]: { json: { type: 'object', required: ['given_name'] } },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result.valid).toBe(true);
    expect(result.schemaAvailable).toBe(true);
    expect(stub.requested).toEqual([BASE_VCT, SCHEMA_URI]);
  });

  it('extends で継承したスキーマが子の検証に効く', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: CHILD_METADATA },
      [BASE_VCT]: { json: BASE_METADATA },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      CHILD_VCT,
      { nickname: 'たろ' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    // 親スキーマの required: given_name が効いて必須違反になる。
    expect(result.valid).toBe(false);
    expect(result.errors?.[0]?.path).toBe('/given_name');
    expect(result.errors?.[0]?.required).toBe(true);
  });

  it('Type Metadata に schema / schema_uri が無ければ構造制約なしとして通過する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: { vct: BASE_VCT, name: 'x' } } });
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { anything: 1 },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [] });
  });

  it('vct が URL でなければ検証をスキップする（従来の文字列 vct 互換）', async () => {
    const result = await validateClaimsAgainstTypeMetadata('urn:example:pid', { a: 1 });
    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [] });
  });
});

describe('validateClaimsAgainstTypeMetadata — 構造不正（3061）は fail-open しない', () => {
  it('vct 不一致（型すり替え）は既定でも 3061 として伝播する', async () => {
    // 監査キー `schema_fetch_failed` で黙って通すと 「vct 一致検証」が無効化される。
    const stub = createFetchStub({
      [BASE_VCT]: { json: { ...BASE_METADATA, vct: 'https://evil.example.com/x' } },
    });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { given_name: '太郎' },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      ),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it('extends の循環も既定で 3061 として伝播する', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT } },
      [BASE_VCT]: { json: { vct: BASE_VCT, extends: CHILD_VCT } },
    });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        CHILD_VCT,
        { given_name: '太郎' },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      ),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it('extends チェーンの子が非配列の claims を返しても 3061 になる（未捕捉 TypeError にしない）', async () => {
    // `child.map` が TypeError を投げると VericertsError ではないため FO-3 の判定を素通りし、
    // 「取得失敗は警告通過」という契約が破れる。取得段階で 3061 に正規化する。
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT, claims: 'x' } },
      [BASE_VCT]: { json: BASE_METADATA },
    });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        CHILD_VCT,
        { given_name: '太郎' },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      ),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });
});

describe('validateClaimsAgainstTypeMetadata — キャッシュ', () => {
  it('schema_uri の取得結果も TTL キャッシュされる', async () => {
    const stub = createFetchStub({
      [BASE_VCT]: { json: { vct: BASE_VCT, schema_uri: SCHEMA_URI } },
      [SCHEMA_URI]: { json: { type: 'object' } },
    });
    const options = { fetchImpl: stub.fetchImpl, ...freshCaches(), nowMs: 1_000 };
    await validateClaimsAgainstTypeMetadata(BASE_VCT, { a: 1 }, options);
    await validateClaimsAgainstTypeMetadata(BASE_VCT, { a: 1 }, options);
    expect(stub.requested).toEqual([BASE_VCT, SCHEMA_URI]);
  });
});
