import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { expectRejects } from '../../__tests__/network-method.fixtures.js';
import { consumeResolutionBody, createResolutionWorkBudget } from '../../resolution-budget.js';
import { ResolutionCache } from '../resolution-cache.js';

describe('ResolutionCache の本文量予算', () => {
  it('別スコープのキャッシュヒットにも取得時の本文量を計上する', async () => {
    const cache = new ResolutionCache<object>(() => 0);
    const document = { id: 'did:example:cached' };
    let loads = 0;
    const load = async () => {
      loads += 1;
      return { value: document, weight: 100 };
    };
    await cache.getOrLoad('did', load);
    const scope = createResolutionWorkBudget(500, 150);
    expect(await cache.getOrLoad('did', load, scope)).toBe(document);
    expect(scope.remainingBodyLength).toBe(50);
    expect(scope.remaining).toBe(500);
    await expectRejects(
      cache.getOrLoad('did', load, scope),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(scope.remainingBodyLength).toBe(0);
    expect(loads).toBe(1);
  });

  it('取得時に消費済みの本文量を二重計上せず、期限切れ後の重みを更新する', async () => {
    let now = 0;
    const cache = new ResolutionCache<object>(() => now);
    const scope = createResolutionWorkBudget(500, 300);
    const load = async (weight: number) => {
      consumeResolutionBody(scope, weight);
      return { value: {}, weight };
    };
    await cache.getOrLoad('did', () => load(100), scope);
    expect(scope.remainingBodyLength).toBe(200);
    now = 600;
    await cache.getOrLoad('did', () => load(120), scope);
    expect(scope.remainingBodyLength).toBe(80);
    const nextScope = createResolutionWorkBudget(500, 150);
    await cache.getOrLoad('did', () => load(100), nextScope);
    expect(nextScope.remainingBodyLength).toBe(30);
  });
});
