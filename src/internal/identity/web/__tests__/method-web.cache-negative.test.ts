/**
 * did:web 解決キャッシュの negative cache と設定拒否の検証。
 *
 * 検証対象:
 * - negative cache: 2003（404 / DNS 失敗）を 30 秒固定で記憶し、その間はネットワークに出ない。
 * - 2010（ドキュメント不正）/ 2001（DID 構文不正）は記憶しない。
 * - 取得成功は記憶済みの失敗を破棄する。
 * - 利用者設定による TTL 上限の緩和拒否（3002）／厳格化の許可。
 * - 例外に DID 文字列・URL が漏れないこと。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createDidWebCache, DID_WEB_CACHE_MAX_TTL_SECONDS } from '../did-web-cache.js';
import { MethodWeb, resolveDidWeb } from '../method-web.js';
import {
  countingFetch,
  DID,
  EXPECTED_URL,
  expectRejectCode,
  fixedClock,
  mockResponse,
  notFoundFetch,
  okFetch,
  recorder,
  SAMPLE_DOC,
} from './did-web-cache.fixtures.js';

describe('did:web キャッシュ — negative cache', () => {
  it('404（2003）は 30 秒間ネットワークに出ずに同じコードを返す', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = notFoundFetch();
    const rec = recorder();
    const deps = { fetchFn, nowSeconds: clock.now, cache, ...rec };

    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);
    expect(calls()).toBe(1);

    clock.advance(29);
    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);
    expect(calls()).toBe(1);
    // ネットワーク I/O が無い経路なので hot として観測される。
    expect(rec.states).toEqual(['cold', 'hot']);
  });

  it('30 秒経過後は再取得する（境界は失効側）', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = notFoundFetch();
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);
    clock.advance(30);
    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);

    expect(calls()).toBe(2);
  });

  it('ネットワークエラー（DNS 失敗相当）も negative cache する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    let calls = 0;
    const fetchFn = (async () => {
      calls += 1;
      throw new TypeError('Failed to fetch');
    }) as unknown as typeof fetch;
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);
    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);

    expect(calls).toBe(1);
  });

  it('DID_DOC_INVALID（2010）は negative cache しない（取得自体は成功しているため）', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = countingFetch(() =>
      mockResponse({ body: '{ not json', contentType: 'application/json' }),
    );
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_DOC_INVALID);
    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_DOC_INVALID);

    expect(calls()).toBe(2);
  });

  it('INVALID_DID（2001）は negative cache せず fetch にも到達しない', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch();
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await expectRejectCode(resolveDidWeb('did:key:z6Mk', deps), ErrorCodes.INVALID_DID);

    expect(calls()).toBe(0);
    expect(cache.size).toBe(0);
  });

  it('取得成功は記憶済みの失敗を破棄する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    let failing = true;
    let calls = 0;
    const fetchFn = (async () => {
      calls += 1;
      return failing
        ? mockResponse({ body: 'Not Found', status: 404, contentType: 'text/plain' })
        : mockResponse({ body: JSON.stringify(SAMPLE_DOC), contentType: 'application/did+json' });
    }) as unknown as typeof fetch;
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);
    clock.advance(30); // negative エントリを失効させる。
    failing = false;
    expect((await resolveDidWeb(DID, deps)).id).toBe(DID);
    expect(calls).toBe(2);

    // 成功後は negative が残っていないので、TTL 内は hot で返る。
    expect((await resolveDidWeb(DID, deps)).id).toBe(DID);
    expect(calls).toBe(2);
  });
});

describe('did:web キャッシュ — 上限設定の緩和拒否', () => {
  it('maxTtlSeconds: 601（緩和）は 3002 で拒否し、ネットワークにも出ない', async () => {
    const { fetchFn, calls } = okFetch();

    await expectRejectCode(
      resolveDidWeb(DID, { fetchFn, maxTtlSeconds: DID_WEB_CACHE_MAX_TTL_SECONDS + 1 }),
      ErrorCodes.VC_SCHEMA_INVALID,
    );

    expect(calls()).toBe(0);
  });

  it('MethodWeb 構築時にも緩和設定を 3002 で拒否する（fail fast）', () => {
    expect(() => new MethodWeb({ maxTtlSeconds: DID_WEB_CACHE_MAX_TTL_SECONDS + 1 })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('maxTtlSeconds: 60（厳格化）は許可し、その TTL で失効する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch('max-age=600');
    const deps = { fetchFn, nowSeconds: clock.now, cache, maxTtlSeconds: 60 };

    await resolveDidWeb(DID, deps);
    clock.advance(59);
    await resolveDidWeb(DID, deps);
    expect(calls()).toBe(1);

    clock.advance(1);
    await resolveDidWeb(DID, deps);
    expect(calls()).toBe(2);
  });

  it('maxTtlSeconds: 600（上限と同値）は許可する', async () => {
    const clock = fixedClock();
    const { fetchFn, calls } = okFetch();
    const method = new MethodWeb({
      fetchFn,
      nowSeconds: clock.now,
      maxTtlSeconds: DID_WEB_CACHE_MAX_TTL_SECONDS,
    });

    await method.resolve(DID);
    await method.resolve(DID);

    expect(calls()).toBe(1);
  });
});

describe('did:web キャッシュ — 例外の情報漏えい防止', () => {
  it('negative cache 経由の再送出にも DID / URL が含まれない', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn } = notFoundFetch();
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);
    const error = await expectRejectCode(resolveDidWeb(DID, deps), ErrorCodes.DID_NOT_FOUND);

    const serialized = `${error.message} ${JSON.stringify(error.context ?? {})}`;
    expect(serialized).not.toContain(DID);
    expect(serialized).not.toContain('example.com');
    expect(serialized).not.toContain(EXPECTED_URL);
  });

  it('上限緩和拒否（3002）の例外にも DID / URL が含まれない', async () => {
    const error = await expectRejectCode(
      resolveDidWeb(DID, { maxTtlSeconds: DID_WEB_CACHE_MAX_TTL_SECONDS + 1 }),
      ErrorCodes.VC_SCHEMA_INVALID,
    );

    const serialized = `${error.message} ${JSON.stringify(error.context ?? {})}`;
    expect(serialized).not.toContain(DID);
    expect(serialized).not.toContain('example.com');
  });
});
