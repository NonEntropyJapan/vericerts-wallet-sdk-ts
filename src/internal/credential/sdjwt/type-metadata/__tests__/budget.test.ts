/**
 * Type Metadata 解決の仕事量予算の回帰テスト。
 *
 * `MAX_DOCUMENT_BYTES`（1 文書 1 MiB）と `MAX_EXTENDS_DEPTH`（10 段）だけでは、`extends` 10 段 × `schema_uri`
 * 10 件 = 20 文書が各 1 MiB で、合計 20 MB・RSS 1 GB 超になった。解決 1 回（または VP 全体）で取得する文書数と
 * 総バイト数を共有の `PresentationWorkBudget` で数える。実時間ではなく、予算の残り・取得回数・エラーコードで決定的に pin する。
 * 形状を変えて検証する: 少数の巨大文書 / 多数の極小文書（キャッシュヒットを含む）/ `extends` と `schema_uri` の入れ子。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import {
  newPresentationWorkBudget,
  PRESENTATION_WORK_LIMITS,
} from '../../../../primitives/presentation-work-budget.js';
import { TypeMetadataCache } from '../cache.js';
import { resolveTypeMetadata, validateClaimsAgainstTypeMetadata } from '../resolve.js';
import type { SdJwtTypeMetadata } from '../types.js';
import { MAX_EXTENDS_DEPTH } from '../types.js';
import { createFetchStub, type StubResponse } from './fixtures.js';

function freshCaches() {
  return {
    metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
    schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
  };
}

async function rejection(promise: Promise<unknown>): Promise<VericertsError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof VericertsError) {
      return err;
    }
    throw err;
  }
  throw new Error('should have thrown');
}

function expectTooLarge(err: VericertsError): void {
  expect(err.code).toBe(ErrorCodes.TYPE_METADATA_INVALID);
  expect(err.context).toMatchObject({ reason: 'metadata_too_large' });
}

const typeUrl = (i: number) => `https://tm.example.com/t${i}`;
const schemaUrl = (i: number) => `https://schema.example.com/s${i}`;

/** 約 `bytes` バイトの Type Metadata 文書（`$comment` で水増し）。 */
function typeDoc(i: number, last: boolean, bytes: number, withSchema: boolean): StubResponse {
  return {
    json: {
      vct: typeUrl(i),
      ...(last ? {} : { extends: typeUrl(i + 1) }),
      ...(withSchema ? { schema_uri: schemaUrl(i) } : {}),
      $comment: 'x'.repeat(bytes),
    },
  };
}

function chainRoutes(depth: number, bytes: number, withSchema: boolean) {
  const routes: Record<string, StubResponse> = {};
  for (let i = 0; i < depth; i += 1) {
    routes[typeUrl(i)] = typeDoc(i, i === depth - 1, bytes, withSchema);
    if (withSchema) {
      routes[schemaUrl(i)] = { json: { type: 'object', $comment: 'y'.repeat(bytes) } };
    }
  }
  return routes;
}

describe('Type Metadata 解決の総量予算', () => {
  it('少数の巨大文書: 各 600 KiB の extends 4 段は総バイト予算で拒否し、残りの文書は取得しない', async () => {
    // 1 文書は 1 MiB 未満で従来の上限を通るが、合計は 2 MiB を超える。
    const stub = createFetchStub(chainRoutes(4, 600 * 1024, false));
    const err = await rejection(
      resolveTypeMetadata(typeUrl(0), { fetchImpl: stub.fetchImpl, ...freshCaches() }),
    );
    expectTooLarge(err);
    // 3 文書目（累計 1.8 MiB）は通り、4 文書目で超過する。それ以降は取りに行かない。
    expect(stub.requested).toHaveLength(4);
  });

  it('入れ子: extends 10 段 × schema_uri 10 件（各 150 KiB = 合計約 3 MB）は 3061 で拒否する', async () => {
    const stub = createFetchStub(chainRoutes(MAX_EXTENDS_DEPTH, 150 * 1024, true));
    const err = await rejection(
      validateClaimsAgainstTypeMetadata(
        typeUrl(0),
        { a: 1 },
        { fetchImpl: stub.fetchImpl, ...freshCaches() },
      ),
    );
    expectTooLarge(err);
    // 全 20 文書は取得に至らない（予算 2 MiB 内で打ち切る）。
    expect(stub.requested.length).toBeLessThan(2 * MAX_EXTENDS_DEPTH);
  });

  it('予算超過は 3060 ではなく 3061: 取得失敗用の fail-open（FO-3）で警告通過しない', async () => {
    const stub = createFetchStub(chainRoutes(4, 600 * 1024, false));
    const consents: unknown[] = [];
    const err = await rejection(
      validateClaimsAgainstTypeMetadata(
        typeUrl(0),
        { a: 1 },
        {
          fetchImpl: stub.fetchImpl,
          ...freshCaches(),
          requestConsent: () => true,
          onPolicyEvent: (record) => {
            consents.push(record);
          },
        },
      ),
    );
    expectTooLarge(err);
    expect(consents).toHaveLength(0);
  });

  it('多数の極小文書: 共有予算を渡した解決は、キャッシュヒットでも文書数を数えて metadataDocuments で拒否する', async () => {
    const budget = newPresentationWorkBudget();
    const stub = createFetchStub(chainRoutes(1, 10, false));
    const caches = freshCaches();
    const options = { fetchImpl: stub.fetchImpl, ...caches, workBudget: budget };
    const limit = PRESENTATION_WORK_LIMITS.metadataDocuments;
    for (let i = 0; i < limit; i += 1) {
      await resolveTypeMetadata(typeUrl(0), options);
    }
    // 取得は初回の 1 回だけ（以降はキャッシュ）。それでも文書数は消費される。
    expect(stub.requested).toHaveLength(1);
    expect(budget.metadataDocuments).toBe(0);
    expectTooLarge(await rejection(resolveTypeMetadata(typeUrl(0), options)));
  });

  it('予算は VP 全体で共有される: 同じ予算を使う別の解決も使い切られた分だけ拒否される', async () => {
    const budget = newPresentationWorkBudget();
    budget.metadataBytes = 1024;
    const stub = createFetchStub(chainRoutes(1, 2000, false));
    const err = await rejection(
      resolveTypeMetadata(typeUrl(0), {
        fetchImpl: stub.fetchImpl,
        ...freshCaches(),
        workBudget: budget,
      }),
    );
    expectTooLarge(err);
  });

  // 回帰テスト: 予算は VP 全体で共有されるので、残量を見て取得を始めたあとに別の VC の解決が
  // 使い切ることがある。本文を読みながら `onBytes` が呼ぶ `spendWork` はそこで 3061 を投げるが、
  // `fetchJsonWithinLimits` の本文読み出しの catch がそれを握り潰して 3060（取得失敗）へ正規化していた。
  // 取得失敗は failSafePolicy の同意と監査記録があれば FO-3 で通過できるため、予算を超えた処理が続く。
  it('取得を始めたあとに予算が尽きたときも、取得失敗ではなく予算超過として返す', async () => {
    const budget = newPresentationWorkBudget();
    const stub = createFetchStub(chainRoutes(1, 2000, false));
    // 応答を返したあと、本文を読み終える前に別の消費者が使い切る状況を作る。
    const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
      const response = await stub.fetchImpl(input);
      budget.metadataBytes = 0;
      return response;
    }) as typeof fetch;

    const err = await rejection(
      resolveTypeMetadata(typeUrl(0), { fetchImpl, ...freshCaches(), workBudget: budget }),
    );

    expectTooLarge(err);
  });

  it('通常の解決（数文書・数 KB）は予算内で成功し、使った分だけ予算が減る', async () => {
    const budget = newPresentationWorkBudget();
    const stub = createFetchStub(chainRoutes(3, 100, true));
    const result = await validateClaimsAgainstTypeMetadata(
      typeUrl(0),
      { a: 1 },
      { fetchImpl: stub.fetchImpl, ...freshCaches(), workBudget: budget },
    );
    expect(result.valid).toBe(true);
    // extends 3 文書 + schema_uri 3 文書。
    expect(PRESENTATION_WORK_LIMITS.metadataDocuments - budget.metadataDocuments).toBe(6);
    expect(budget.metadataBytes).toBeLessThan(PRESENTATION_WORK_LIMITS.metadataBytes);
  });
});

describe('Type Metadata 文書内の配列の上限', () => {
  const resolveWith = (document: Record<string, unknown>) => {
    const stub = createFetchStub({ [typeUrl(0)]: { json: { vct: typeUrl(0), ...document } } });
    return resolveTypeMetadata(typeUrl(0), { fetchImpl: stub.fetchImpl, ...freshCaches() });
  };

  it.each([
    ['claims', { claims: Array.from({ length: 129 }, (_, i) => ({ path: [`c${i}`] })) }],
    ['display', { display: Array.from({ length: 65 }, () => ({ lang: 'ja', name: 'n' })) }],
  ])('%s が上限超過の文書は 3061（metadata_too_large）', async (_name, document) => {
    expectTooLarge(await rejection(resolveWith(document)));
  });

  it.each([
    ['空オブジェクト', {}],
    ['path が配列でない', { path: 'x' }],
    ['数値', 0],
    ['null', null],
  ])('claims の要素が %s の文書は 3061（claims_entry_invalid）', async (_name, entry) => {
    const err = await rejection(resolveWith({ claims: [entry] }));
    expect(err.code).toBe(ErrorCodes.TYPE_METADATA_INVALID);
    expect(err.context).toMatchObject({ reason: 'claims_entry_invalid' });
  });

  it('上限ちょうど（claims 128・display 64）の文書は受理し、マージ結果にも全件が残る', async () => {
    const claims = Array.from({ length: 128 }, (_, i) => ({ path: [`c${i}`] }));
    const display = Array.from({ length: 64 }, () => ({ lang: 'ja', name: 'n' }));
    const resolved = await resolveWith({ claims, display });
    expect(resolved.metadata.claims).toHaveLength(128);
  });
});
