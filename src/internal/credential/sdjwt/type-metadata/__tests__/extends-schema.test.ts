/**
 * `extends` チェーン上の全スキーマ評価（SD-JWT VC §6.5.2 MUST）の回帰テスト。
 *
 * 以前は `mergeMetadata` で子が親の `schema` / `schema_uri` を丸ごと置換したあと 1 つだけ評価していた。
 * 派生型の作者（= 発行者）が `schema: {}` を書くだけで基底型の必須属性・型制約を迂回できた。
 *
 * 検証内容:
 * - 子が緩い（空の）`schema` を持っても、親の必須属性違反は拒否される。
 * - 逆に、子の制約違反も（親が満たしていても）拒否される。
 * - 親が `schema_uri`、子がインライン `schema`（混在）でも両方評価される。
 * - 3 段（祖父 → 親 → 子）の祖父のスキーマも評価される。
 * - 全スキーマを満たすクレームは valid。スキーマを持たない中間文書は評価に影響しない。
 * - 祖先の `schema_uri` 取得失敗は握りつぶさず 3060（FO-3 通過の同意が無い既定）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { TypeMetadataCache } from '../cache.js';
import { validateClaimsAgainstTypeMetadata } from '../resolve.js';
import type { SdJwtTypeMetadata } from '../types.js';
import { BASE_VCT, CHILD_VCT, createFetchStub, SCHEMA_URI } from './fixtures.js';

const MID_VCT = 'https://issuer.example.com/vct/mid/1.0';

function freshCaches() {
  return {
    metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
    schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
  };
}

const BASE_SCHEMA = {
  type: 'object',
  required: ['given_name'],
  properties: { given_name: { type: 'string', minLength: 1 } },
};

describe('validateClaimsAgainstTypeMetadata — extends の schema は全件評価', () => {
  it('子が空 schema でも、親の必須属性違反は valid:false', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT, schema: {} } },
      [BASE_VCT]: { json: { vct: BASE_VCT, schema: BASE_SCHEMA } },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      CHILD_VCT,
      { family_name: 'Doe' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result.valid).toBe(false);
    expect(result.schemaAvailable).toBe(true);
  });

  it('子が空 schema でも、親の型制約違反（minLength）は valid:false', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT, schema: {} } },
      [BASE_VCT]: { json: { vct: BASE_VCT, schema: BASE_SCHEMA } },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      CHILD_VCT,
      { given_name: '' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result.valid).toBe(false);
  });

  it('子の制約違反も、親が満たしていても valid:false', async () => {
    const childSchema = {
      type: 'object',
      required: ['age'],
      properties: { age: { type: 'integer' } },
    };
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT, schema: childSchema } },
      [BASE_VCT]: { json: { vct: BASE_VCT, schema: BASE_SCHEMA } },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      CHILD_VCT,
      { given_name: 'Taro' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result.valid).toBe(false);
  });

  it('親・子の全スキーマを満たすクレームは valid:true', async () => {
    const childSchema = {
      type: 'object',
      required: ['age'],
      properties: { age: { type: 'integer' } },
    };
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT, schema: childSchema } },
      [BASE_VCT]: { json: { vct: BASE_VCT, schema: BASE_SCHEMA } },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      CHILD_VCT,
      { given_name: 'Taro', age: 30 },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result.valid).toBe(true);
    expect(result.schemaAvailable).toBe(true);
  });

  it('親が schema_uri・子がインライン schema の混在でも親の違反を拒否する', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT, schema: {} } },
      [BASE_VCT]: { json: { vct: BASE_VCT, schema_uri: SCHEMA_URI } },
      [SCHEMA_URI]: { json: BASE_SCHEMA },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      CHILD_VCT,
      { family_name: 'Doe' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result.valid).toBe(false);
  });

  it('3 段チェーンでは祖父のスキーマも評価され、schema を持たない中間は影響しない', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: MID_VCT, schema: {} } },
      [MID_VCT]: { json: { vct: MID_VCT, extends: BASE_VCT } },
      [BASE_VCT]: { json: { vct: BASE_VCT, schema: BASE_SCHEMA } },
    });
    const bad = await validateClaimsAgainstTypeMetadata(
      CHILD_VCT,
      {},
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(bad.valid).toBe(false);
    const good = await validateClaimsAgainstTypeMetadata(
      CHILD_VCT,
      { given_name: 'Taro' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(good.valid).toBe(true);
  });

  it('祖先の schema_uri が取得できなければ握りつぶさず 3060（既定は fail-closed）', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT, schema: {} } },
      [BASE_VCT]: { json: { vct: BASE_VCT, schema_uri: SCHEMA_URI } },
      [SCHEMA_URI]: { networkError: true },
    });
    let caught: unknown;
    try {
      await validateClaimsAgainstTypeMetadata(
        CHILD_VCT,
        { given_name: 'Taro' },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      );
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.TYPE_METADATA_FETCH_FAILED);
  });
});
