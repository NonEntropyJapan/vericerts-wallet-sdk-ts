/**
 * Type Metadata 経路のハードニング（回帰テスト）。
 *
 * Type Metadata の取得失敗（FO-3）と完全性検査の失敗を区別する。完全性を保証できない場合は拒否する（3060 / 3061）。
 *
 * 検証内容:
 * - 非 HTTPS URL（`vct` / `extends`）は入口によらず **3060** に統一する。
 * - `claims` / `display` が配列でない文書は **3061**（未捕捉 `TypeError` にしない）。
 * - 検証手段の無い `#integrity` は黙って捨てず **3061** で拒否する。
 * - TTL キャッシュはエントリ数に上限を持ち、超過分を古い順に追い出す。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { TypeMetadataCache } from '../cache.js';
import { resolveTypeMetadata } from '../resolve.js';
import type { SdJwtTypeMetadata } from '../types.js';
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

describe('resolveTypeMetadata — 非 HTTPS URL は 3060 に統一する', () => {
  it('vct が HTTPS URL でなければ 3060 で拒否する', async () => {
    // 共有プリミティブ（json-schema/fetch-document.ts）が同条件で使うコードに合わせる。
    await expectCode(
      resolveTypeMetadata('urn:example:not-a-url', freshCaches()),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('http:// の vct は 3060 で拒否する（平文降格の防止）', async () => {
    await expectCode(
      resolveTypeMetadata('http://issuer.example.com/vct/a', freshCaches()),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('extends が HTTPS URL でなければ 3060 で拒否する', async () => {
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { vct: CHILD_VCT, extends: 'http://issuer.example.com/vct/base' } },
    });
    await expectCode(
      resolveTypeMetadata(CHILD_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });
});

describe('assertTypeMetadata — claims / display の配列性（3061）', () => {
  it.each([
    ['claims', { claims: 'x' }],
    ['display', { display: { lang: 'ja-JP' } }],
  ])('%s が配列でなければ 3061 で拒否する', async (_label, extra) => {
    const stub = createFetchStub({ [BASE_VCT]: { json: { ...BASE_METADATA, ...extra } } });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });

  it('extends チェーンの子が非配列の claims を返しても TypeError にならない', async () => {
    // マージは `claims` を配列前提で扱うため、型検査が無いと `child.map is not a function` が
    // VericertsError 以外の例外として漏れ、FO-3 の fail-open catch を素通りする。
    const stub = createFetchStub({
      [CHILD_VCT]: { json: { ...CHILD_METADATA, claims: 'x' } },
      [BASE_VCT]: { json: BASE_METADATA },
    });
    await expectCode(
      resolveTypeMetadata(CHILD_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });
});

describe('assertTypeMetadata — 検証できない #integrity（3061）', () => {
  it.each([
    ['extends#integrity'],
    ['schema_uri#integrity'],
  ])('%s が宣言された文書は黙って通さず 3061 で拒否する', async (key) => {
    // SDK は SRI を検証できない。宣言を捨てて通すと、Issuer が固定したハッシュが無視され
    // スキーマホスト乗っ取りによる文書すり替えを検知できない。
    const stub = createFetchStub({
      [BASE_VCT]: { json: { ...BASE_METADATA, [key]: 'sha256-abc' } },
    });
    await expectCode(
      resolveTypeMetadata(BASE_VCT, { fetchImpl: stub.fetchImpl, ...freshCaches() }),
      ErrorCodes.TYPE_METADATA_INVALID,
    );
  });
});

describe('TypeMetadataCache — エントリ数の上限', () => {
  it('上限を超えたら古いエントリから追い出す（無制限に積み上げない）', () => {
    // キー（vct / schema_uri）は Issuer が自由に決められるため、上限が無いと毎回異なる URL の
    // クレデンシャルを流すだけでメモリが際限なく伸びる。
    const cache = new TypeMetadataCache<SdJwtTypeMetadata>(60_000, 2);
    const doc = (vct: string): SdJwtTypeMetadata => ({ vct });

    cache.set('https://a.example.com/1', doc('a'), 0);
    cache.set('https://b.example.com/1', doc('b'), 0);
    cache.set('https://c.example.com/1', doc('c'), 0);

    expect(cache.get('https://a.example.com/1', 0)).toBeUndefined();
    expect(cache.get('https://b.example.com/1', 0)?.vct).toBe('b');
    expect(cache.get('https://c.example.com/1', 0)?.vct).toBe('c');
  });

  it('同一キーの上書きはエントリ数を増やさない', () => {
    const cache = new TypeMetadataCache<SdJwtTypeMetadata>(60_000, 2);

    cache.set('https://a.example.com/1', { vct: 'a' }, 0);
    cache.set('https://a.example.com/1', { vct: 'a2' }, 0);
    cache.set('https://b.example.com/1', { vct: 'b' }, 0);

    expect(cache.get('https://a.example.com/1', 0)?.vct).toBe('a2');
    expect(cache.get('https://b.example.com/1', 0)?.vct).toBe('b');
  });
});
