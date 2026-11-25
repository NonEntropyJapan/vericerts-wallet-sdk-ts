/**
 * `metadataCache` / `schemaCache` DI の鎖読みによる Type Metadata 差し替え。
 *
 * `options.metadataCache ?? default` と鎖読みすると、`Object.prototype.metadataCache` の汚染で
 * 攻撃者の `get()` が返す Type Metadata が fetch 0 回のまま採用される。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../../__tests__/prototype-pollution.fixtures.js';
import { TypeMetadataCache } from '../../cache.js';
import { resolveTypeMetadata } from '../../resolve.js';
import type { SdJwtTypeMetadata } from '../../types.js';
import { BASE_METADATA, BASE_VCT, createFetchStub } from '../fixtures.js';

const EVIL_METADATA = { vct: BASE_VCT, name: 'ATTACKER' };
const EVIL_CACHE = { get: () => EVIL_METADATA, set: () => undefined };

describe('metadataCache / schemaCache の汚染耐性', () => {
  it('Object.prototype.metadataCache を汚染しても正規の Type Metadata を fetch して返す', async () => {
    // 既定キャッシュはモジュール共有のため、他テストの取得結果が漏れない専用 vct を使う。
    const vct = `${BASE_VCT}?case=pollution`;
    const stub = createFetchStub({ [vct]: { json: { ...BASE_METADATA, vct } } });
    const resolved = await withPollutedPrototypeAsync({ metadataCache: EVIL_CACHE }, () =>
      resolveTypeMetadata(vct, {
        fetchImpl: stub.fetchImpl,
        schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
      }),
    );
    expect(stub.requested).toEqual([vct]);
    expect(resolved.metadata.name).toBe(BASE_METADATA.name);
  });

  it('明示的に注入した metadataCache は従来どおり使われる', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const options = {
      fetchImpl: stub.fetchImpl,
      metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
      schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
      nowMs: 1000,
    };
    await resolveTypeMetadata(BASE_VCT, options);
    await resolveTypeMetadata(BASE_VCT, options);
    expect(stub.requested).toEqual([BASE_VCT]);
  });
});
