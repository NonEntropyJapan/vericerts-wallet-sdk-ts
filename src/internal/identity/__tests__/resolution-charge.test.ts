/**
 * BoundedResolver の予算計上は「全 DID メソッドの解決経路で必ず通る共通の入口」で行う。
 *
 * メソッド側が予算を一切呼ばない（呼び忘れた）resolver を載せても、返した DID Document の保持量が
 * スコープの本文量予算から引かれることを、サイズと件数の比率を変えた複数形状で pin する。
 * 実時間ではなく、成功した解決の件数・例外の種別・`reason`・予算の残りという決定的な値で検証する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../errors.js';
import { createBoundedResolver, type DidResolverLike } from '../bounded-resolver.js';
import type { DIDDocument, VerificationMethod } from '../did.js';
import {
  consumeResolutionBody,
  createResolutionWorkBudget,
  DEFAULT_MAX_SCOPE_BODY_LENGTH,
  type ResolutionWorkBudget,
} from '../resolution-budget.js';
import { estimateJsonLength, resolveWithinScope } from '../resolution-charge.js';

/** 予算を一切呼ばずに、指定形状の文書を返す resolver（= 押し忘れたメソッド）。 */
function forgetfulResolver(shape: (did: string) => DIDDocument): DidResolverLike {
  return { resolve: async (did) => shape(did) };
}

function vm(did: string, index: number, keyLength: number): VerificationMethod {
  return {
    id: `${did}#k${index}`,
    type: 'Multikey',
    controller: did,
    publicKeyMultibase: `z${'a'.repeat(keyLength)}`,
  };
}

/** 鍵 `keyCount` 個 × 各 `keyLength` 文字の文書。サイズと件数の比率を変えて同じ総量を作る。 */
function documentOf(did: string, keyCount: number, keyLength: number): DIDDocument {
  const keys = Array.from({ length: keyCount }, (_, i) => vm(did, i, keyLength));
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: keys,
    authentication: [],
    assertionMethod: [],
  };
}

async function settle(
  resolver: DidResolverLike,
  count: number,
): Promise<PromiseSettledResult<DIDDocument>[]> {
  const results: PromiseSettledResult<DIDDocument>[] = [];
  for (let i = 0; i < count; i++) {
    const [result] = await Promise.allSettled([resolver.resolve(`did:example:${i}`)]);
    results.push(result as PromiseSettledResult<DIDDocument>);
  }
  return results;
}

function expectWorkLimit(result: PromiseSettledResult<unknown>): void {
  expect(result.status).toBe('rejected');
  const error = (result as PromiseRejectedResult).reason as VericertsError;
  expect(error.code).toBe(ErrorCodes.INVALID_DID);
  expect(error.context?.reason).toBe('resolution_work_limit');
}

describe('estimateJsonLength', () => {
  it.each([
    ['空オブジェクト', {}],
    ['入れ子', { a: 'xy', b: [1, 2, { c: 'z' }], d: {} }],
    ['文字列配列', ['a', 'bb', 'ccc']],
    ['null を含む', { a: null, b: [] }],
  ])('%s: コンパクトな JSON 長を超えて数えない', (_name, value) => {
    const actual = JSON.stringify(value).length;
    const estimate = estimateJsonLength(value, Number.MAX_SAFE_INTEGER);
    expect(estimate).toBeLessThanOrEqual(actual);
    // 区切り以外（文字列・キー・括弧）は数えるので、数値・真偽値・null ぶんの差だけに収まる。
    expect(actual - estimate).toBeLessThanOrEqual(3 * 4);
  });

  it('文字列だけの構造は JSON 長と一致する', () => {
    const value = { id: 'did:x:1', list: ['a', 'bb'], nested: { k: 'v' } };
    expect(estimateJsonLength(value, Number.MAX_SAFE_INTEGER)).toBe(JSON.stringify(value).length);
  });

  it('上限を超えたら歩行を打ち切り、cap + 1 以上を返す（入れ子の深い側は辿らない）', () => {
    // 各階層が 100 文字の文字列を 1 つずつ持つ入れ子。cap を超えた時点で以降の階層は辿らない。
    let nested: unknown = 'leaf';
    for (let i = 0; i < 10_000; i++) {
      nested = { s: 'a'.repeat(100), next: nested };
    }
    const estimate = estimateJsonLength(nested, 1_000);
    expect(estimate).toBeGreaterThan(1_000);
    expect(estimate).toBeLessThan(1_000 + 1_000);
  });
});

describe('resolveWithinScope / BoundedResolver: 予算を呼び忘れたメソッドも保持量で縛る', () => {
  // 総量 = keyCount × keyLength がスコープ上限（4 MiB）をまたぐ形状。1 件の大きさと件数の比率を変える。
  const shapes = [
    // [名前, 鍵数, 鍵あたり文字数, 文書あたりの概算文字数]
    ['大きな文書が少数（1 鍵 × 1 MiB）', 1, 1024 * 1024],
    ['中程度の文書（16 鍵 × 64 KiB）', 16, 64 * 1024],
    ['小さな鍵を大量（4096 鍵 × 256 文字）', 4096, 256],
  ] as const;

  it.each(
    shapes,
  )('%s: 予算を超えた解決から fail-closed（件数は決定的）', async (_n, keyCount, keyLength) => {
    const perDocument = estimateJsonLength(
      documentOf('did:example:0', keyCount, keyLength),
      Number.MAX_SAFE_INTEGER,
    );
    const admitted = Math.floor(DEFAULT_MAX_SCOPE_BODY_LENGTH / perDocument);
    expect(admitted).toBeGreaterThanOrEqual(1);
    expect(admitted).toBeLessThan(32);

    const resolver = createBoundedResolver(
      forgetfulResolver((did) => documentOf(did, keyCount, keyLength)),
    );
    const results = await settle(resolver, 32);

    expect(results.slice(0, admitted).every((r) => r.status === 'fulfilled')).toBe(true);
    // 超過した 1 件目以降はすべて拒否される（予算超過のスコープは使い切り扱い）。
    for (const result of results.slice(admitted)) {
      expectWorkLimit(result);
    }
  });

  it('予算内の小さな文書は 32 件すべて解決できる（正常系を壊さない）', async () => {
    const resolver = createBoundedResolver(forgetfulResolver((did) => documentOf(did, 2, 64)));
    const results = await settle(resolver, 32);
    expect(results.every((r) => r.status === 'fulfilled')).toBe(true);
  });

  it('maxBodyLength を絞ると、そのぶんだけ保持量で拒否される（件数 × サイズの比率で同じ総量）', async () => {
    const documentLength = estimateJsonLength(documentOf('did:example:0', 4, 100), 1e9);
    for (const admitted of [1, 3, 7]) {
      const resolver = createBoundedResolver(
        forgetfulResolver((did) => documentOf(did, 4, 100)),
        { maxBodyLength: documentLength * admitted + 1 },
      );
      const results = await settle(resolver, 10);
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(admitted);
    }
  });

  it('メソッドが本文量を計上済みなら、戻り値の保持量で二重に数えない', async () => {
    const budget: ResolutionWorkBudget = createResolutionWorkBudget(1_000, 10_000);
    const doc = documentOf('did:example:0', 1, 500);
    const length = estimateJsonLength(doc, 1e9);
    const resolved = await resolveWithinScope(budget, async (scope) => {
      consumeResolutionBody(scope, length);
      return doc;
    });
    expect(resolved).toBe(doc);
    expect(budget.remainingBodyLength).toBe(10_000 - length);
  });

  it('メソッドの計上が文書より小さければ、差分を共通の入口が補う', async () => {
    const budget = createResolutionWorkBudget(1_000, 10_000);
    const doc = documentOf('did:example:0', 1, 500);
    const length = estimateJsonLength(doc, 1e9);
    await resolveWithinScope(budget, async (scope) => {
      consumeResolutionBody(scope, 10);
      return doc;
    });
    expect(budget.remainingBodyLength).toBe(10_000 - length);
  });

  it('予算を渡さない単独解決（下位 resolver 直接）は計上しない', async () => {
    const direct = forgetfulResolver((did) => documentOf(did, 1, 2 * 1024 * 1024));
    await expect(direct.resolve('did:example:0')).resolves.toBeDefined();
  });

  it('同一 DID の再解決は共有結果を返し、保持量を二重に計上しない', async () => {
    const keyLength = 1024 * 1024;
    const resolver = createBoundedResolver(
      forgetfulResolver((did) => documentOf(did, 1, keyLength)),
    );
    for (let i = 0; i < 20; i++) {
      await resolver.resolve('did:example:same');
    }
    // 1 MiB 級の文書 1 件ぶんしか消費していないので、別の DID がまだ 2 件通る。
    await resolver.resolve('did:example:other1');
    await resolver.resolve('did:example:other2');
  });
});
