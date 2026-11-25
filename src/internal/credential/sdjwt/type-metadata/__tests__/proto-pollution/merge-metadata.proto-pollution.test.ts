/**
 * `extends` チェーンのマージ結果の `Object.prototype` 汚染耐性。
 *
 * 取得した Type Metadata は `parseJsonWithoutPrototype` により入れ子まで `null` プロトタイプだが、
 * `mergeMetadata` がオブジェクトリテラル展開（`{ ...parent, ...child }`）でマージすると、
 * **結果だけが `Object.prototype` を継承**してその保証が失われる。`schema` / `schema_uri` を
 * どちらの文書も持たない 2 段チェーンで `Object.prototype.schema_uri` が汚染されていると、
 * `loadSchema` が継承値を拾って**攻撃者の URL からスキーマを取得**し、それでクレームを検証する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../../__tests__/prototype-pollution.fixtures.js';
import { TypeMetadataCache } from '../../cache.js';
import { resolveTypeMetadata, validateClaimsAgainstTypeMetadata } from '../../resolve.js';
import type { SdJwtTypeMetadata } from '../../types.js';
import { BASE_VCT, CHILD_METADATA, CHILD_VCT, createFetchStub } from '../fixtures.js';

const EVIL_SCHEMA_URI = 'https://evil.example.com/schema.json';

/** テストごとに独立したキャッシュを使う（モジュール既定の共有キャッシュを汚さない）。 */
function freshCaches() {
  return {
    metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
    schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
  };
}

/**
 * `schema` / `schema_uri` を持たない親。共有の `BASE_METADATA` は `schema` を持つため、
 * 「どちらの文書も定義していないときに継承値を拾うか」を見るにはこの変種が要る。
 */
const SCHEMA_LESS_BASE = {
  vct: BASE_VCT,
  name: 'Base Credential',
  claims: [{ path: ['given_name'], display: [{ lang: 'ja-JP', label: '名' }] }],
};

/** 親 + 子（いずれも `schema` / `schema_uri` を持たない）の 2 段チェーンを返す。 */
function schemaLessChainStub() {
  // 子（CHILD_METADATA）は `extends: BASE_VCT` を持つが schema 系メンバは持たない。
  return createFetchStub({
    [CHILD_VCT]: { json: CHILD_METADATA },
    [BASE_VCT]: { json: SCHEMA_LESS_BASE },
  });
}

describe('extends マージ結果の汚染耐性', () => {
  it('継承した schema_uri はマージ結果から読めない', async () => {
    // 汚染下で読まないと意味が無い（解除後は鎖読みでも undefined になりトートロジーになる）。
    const observed = await withPollutedPrototypeAsync({ schema_uri: EVIL_SCHEMA_URI }, async () => {
      const stub = schemaLessChainStub();
      const resolved = await resolveTypeMetadata(CHILD_VCT, {
        fetchImpl: stub.fetchImpl,
        ...freshCaches(),
      });
      return {
        schemaUri: resolved.metadata.schema_uri,
        prototype: Object.getPrototypeOf(resolved.metadata) as object | null,
      };
    });
    expect(observed.schemaUri).toBeUndefined();
    // 取得文書と同じく、マージ結果も `null` プロトタイプであること（欠陥の根）。
    expect(observed.prototype).toBeNull();
  });

  it('継承した schema はマージ結果から読めない', async () => {
    const observed = await withPollutedPrototypeAsync(
      { schema: { type: 'object', required: ['attacker_controlled'] } },
      async () => {
        const stub = schemaLessChainStub();
        const resolved = await resolveTypeMetadata(CHILD_VCT, {
          fetchImpl: stub.fetchImpl,
          ...freshCaches(),
        });
        return resolved.metadata.schema;
      },
    );
    expect(observed).toBeUndefined();
  });

  it('継承した schema_uri から攻撃者のスキーマを取得しない', async () => {
    const stub = schemaLessChainStub();
    const result = await withPollutedPrototypeAsync({ schema_uri: EVIL_SCHEMA_URI }, async () =>
      validateClaimsAgainstTypeMetadata(
        CHILD_VCT,
        { given_name: '花子' },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      ),
    );
    expect(stub.requested).not.toContain(EVIL_SCHEMA_URI);
    // schema / schema_uri なし = 構造制約なしの通過（取得失敗の FO-3 警告通過ではない）。
    expect(result.valid).toBe(true);
    expect(result.schemaAvailable).toBe(false);
    expect(result.warnings).toEqual([]);
  });
});
