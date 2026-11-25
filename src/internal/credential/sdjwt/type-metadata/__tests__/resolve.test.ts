/**
 * SD-JWT VC Type Metadata resolver のユニットテスト。
 *
 * draft-ietf-oauth-sd-jwt-vc §6 に沿った Type Metadata 解決を検証する。
 *
 * 検証内容:
 * - `vct` が HTTPS URL のとき Type Metadata を取得し、`vct` 一致を検証する。
 * - `extends` を辿ってマージし、同名メンバは子が優先する。`claims` は path 単位で統合する。
 * - `extends` の循環・深さ超過を 3061 で拒否する。
 * - `vct` 不一致 / `schema` と `schema_uri` の併記 / 型不正を 3061 で拒否する。
 * - 取得失敗（ネットワーク / 非 2xx / 非 JSON Content-Type / 非 HTTPS リダイレクト）を 3060 で拒否する。
 *
 * 非 HTTPS URL のコード統一・`#integrity`・`claims` / `display` の型・キャッシュ上限は
 * `hardening.test.ts` で検証する。
 * - TTL キャッシュが効き、同一 `vct` の再解決でネットワーク往復が発生しない。TTL 超過で再取得する。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { TypeMetadataCache } from '../cache.js';
import { resolveTypeMetadata } from '../resolve.js';
import type { SdJwtTypeMetadata } from '../types.js';
import { TYPE_METADATA_CACHE_TTL_MS } from '../types.js';
import { BASE_METADATA, BASE_VCT, CHILD_METADATA, CHILD_VCT, createFetchStub } from './fixtures.js';

/** テストごとに独立したキャッシュを使う（モジュール既定の共有キャッシュを汚さない）。 */
function freshCaches() {
  return {
    metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
    schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
  };
}

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

describe('resolveTypeMetadata — 取得と extends 解決', () => {
  it('単独の Type Metadata を取得する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const resolved = await resolveTypeMetadata(BASE_VCT, {
      fetchImpl: stub.fetchImpl,
      ...freshCaches(),
    });
    expect(resolved.metadata.vct).toBe(BASE_VCT);
    expect(resolved.chain).toEqual([BASE_VCT]);
  });

  it('extends を辿り、同名メンバは子が優先する', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: CHILD_METADATA },
      [BASE_VCT]: { json: BASE_METADATA },
    });
    const resolved = await resolveTypeMetadata(CHILD_VCT, {
      fetchImpl: stub.fetchImpl,
      ...freshCaches(),
    });
    expect(resolved.chain).toEqual([CHILD_VCT, BASE_VCT]);
    // 子が上書き。
    expect(resolved.metadata.vct).toBe(CHILD_VCT);
    expect(resolved.metadata.name).toBe('Identity Credential');
    // 子が持たないメンバは親から継承。
    expect(resolved.metadata.description).toBe('基底の VC 種別');
    expect(resolved.metadata.schema).toEqual(BASE_METADATA.schema);
  });

  it('解決済みの extends は結果に残さない', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: CHILD_METADATA },
      [BASE_VCT]: { json: BASE_METADATA },
    });
    const resolved = await resolveTypeMetadata(CHILD_VCT, {
      fetchImpl: stub.fetchImpl,
      ...freshCaches(),
    });
    expect(resolved.metadata.extends).toBeUndefined();
  });

  it('claims は path 単位で統合し、子の定義が親を置き換える', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: CHILD_METADATA },
      [BASE_VCT]: { json: BASE_METADATA },
    });
    const resolved = await resolveTypeMetadata(CHILD_VCT, {
      fetchImpl: stub.fetchImpl,
      ...freshCaches(),
    });
    const claims = resolved.metadata.claims as ReadonlyArray<Record<string, unknown>>;
    // given_name は親のまま残り、nickname は子の定義で置き換わる（重複しない）。
    expect(claims).toHaveLength(2);
    const byPath = new Map(claims.map((c) => [JSON.stringify(c.path), c]));
    expect(byPath.get('["given_name"]')?.display).toEqual([{ lang: 'ja-JP', label: '名' }]);
    expect(byPath.get('["nickname"]')?.display).toEqual([{ lang: 'ja-JP', label: 'ニックネーム' }]);
  });

  it('子が schema_uri を持つ場合、親の schema は引き継がない（併記を作らない）', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { ...CHILD_METADATA, schema_uri: 'https://x.example.com/s.json' } },
      [BASE_VCT]: { json: BASE_METADATA },
    });
    const resolved = await resolveTypeMetadata(CHILD_VCT, {
      fetchImpl: stub.fetchImpl,
      ...freshCaches(),
    });
    expect(resolved.metadata.schema).toBeUndefined();
    expect(resolved.metadata.schema_uri).toBe('https://x.example.com/s.json');
  });
});

describe('resolveTypeMetadata — 構造不正（3061）', () => {
  it('文書の vct が取得元 URL と一致しなければ拒否する（種別すり替えの防止）', async () => {
    const stub = createFetchStub({
      [BASE_VCT]: { json: { ...BASE_METADATA, vct: 'https://evil.example.com/other' } },
    });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it('schema と schema_uri の併記を拒否する', async () => {
    const stub = createFetchStub({
      [BASE_VCT]: { json: { ...BASE_METADATA, schema_uri: 'https://x.example.com/s.json' } },
    });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it('schema が object でなければ拒否する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: { vct: BASE_VCT, schema: 'nope' } } });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it('extends の循環を検知する', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: BASE_VCT } },
      [BASE_VCT]: { json: { vct: BASE_VCT, extends: CHILD_VCT } },
    });
    await expectCode(
      resolveTypeMetadata(CHILD_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it('extends が深すぎる場合に打ち切る', async () => {
    // 自己参照を作らずに 11 段以上のチェーンを構成する。
    const routes: Record<string, { json: unknown }> = {};
    for (let i = 0; i < 15; i += 1) {
      const url = `https://issuer.example.com/vct/level-${i}`;
      routes[url] = {
        json: { vct: url, extends: `https://issuer.example.com/vct/level-${i + 1}` },
      };
    }
    const stub = createFetchStub(routes);
    await expectCode(
      resolveTypeMetadata('https://issuer.example.com/vct/level-0', {
        fetchImpl: stub.fetchImpl,
        ...freshCaches(),
      }),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });
});

describe('resolveTypeMetadata — 取得失敗（3060）', () => {
  it('ネットワークエラーを 3060 に正規化する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { networkError: true } });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('非 2xx を 3060 に正規化する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA, status: 404 } });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('JSON 以外の Content-Type を拒否する', async () => {
    const stub = createFetchStub({
      [BASE_VCT]: { json: BASE_METADATA, contentType: 'text/html' },
    });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('application/vc+json のような +json サフィックスは受理する', async () => {
    const stub = createFetchStub({
      [BASE_VCT]: { json: BASE_METADATA, contentType: 'application/vc+json; charset=utf-8' },
    });
    const resolved = await resolveTypeMetadata(BASE_VCT, {
      fetchImpl: stub.fetchImpl,
      ...freshCaches(),
    });
    expect(resolved.metadata.vct).toBe(BASE_VCT);
  });

  it('JSON パース失敗を 3060 に正規化する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { body: 'not json' } });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('HTTPS 以外へリダイレクトされたら拒否する', async () => {
    const stub = createFetchStub({
      [BASE_VCT]: { json: BASE_METADATA, finalUrl: 'http://evil.example.com/vct' },
    });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('JSON 配列を返された場合は拒否する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: [1, 2, 3] } });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });
});

describe('resolveTypeMetadata — キャッシュ', () => {
  it('TTL 内の再解決ではネットワーク往復が発生しない', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const caches = freshCaches();
    const options = { fetchImpl: stub.fetchImpl, ...caches, nowMs: 1_000 };
    await resolveTypeMetadata(BASE_VCT, options);
    await resolveTypeMetadata(BASE_VCT, options);
    expect(stub.requested).toEqual([BASE_VCT]);
  });

  it('TTL 超過で再取得する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const caches = freshCaches();
    await resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...caches, nowMs: 1_000 });
    await resolveTypeMetadata(BASE_VCT, {
      fetchImpl: stub.fetchImpl,
      ...caches,
      nowMs: 1_000 + TYPE_METADATA_CACHE_TTL_MS,
    });
    expect(stub.requested).toEqual([BASE_VCT, BASE_VCT]);
  });

  it('extends チェーンの各段もキャッシュされる', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: CHILD_METADATA },
      [BASE_VCT]: { json: BASE_METADATA },
    });
    const caches = freshCaches();
    const options = { fetchImpl: stub.fetchImpl, ...caches, nowMs: 1_000 };
    await resolveTypeMetadata(CHILD_VCT, options);
    await resolveTypeMetadata(CHILD_VCT, options);
    expect(stub.requested).toEqual([CHILD_VCT, BASE_VCT]);
  });
});
