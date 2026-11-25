/**
 * did:web 解決キャッシュの TTL 挙動検証。
 *
 * 時計（`nowSeconds`）と `fetchFn` を注入して決定的に検証する。検証対象:
 * - cold / warm / hot の観測（`cache` ラベル）。
 * - `Cache-Control: max-age` の尊重と、TTL 上限 600 秒でのキャップ。
 * - `no-store` / `no-cache` によるキャッシュ無効化。
 *
 * negative cache と設定拒否は `method-web.cache-negative.test.ts` で検証する。
 */

import { describe, expect, it } from 'bun:test';
import {
  createDidWebCache,
  DID_WEB_CACHE_MAX_ENTRY_LENGTH,
  DID_WEB_CACHE_MAX_TOTAL_LENGTH,
  DID_WEB_CACHE_MAX_TTL_SECONDS,
} from '../did-web-cache.js';
import { MethodWeb, resolveDidWeb } from '../method-web.js';
import {
  countingFetch,
  DID,
  fixedClock,
  mockResponse,
  okFetch,
  recorder,
  SAMPLE_DOC,
} from './did-web-cache.fixtures.js';

describe('did:web キャッシュ — cold / warm / hot', () => {
  it('初回解決は cold で取得する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch();
    const rec = recorder();

    const doc = await resolveDidWeb(DID, { fetchFn, nowSeconds: clock.now, cache, ...rec });

    expect(doc.id).toBe(DID);
    expect(calls()).toBe(1);
    expect(rec.states).toEqual(['cold']);
  });

  it('TTL 内の 2 回目は hot でネットワークに出ない', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch();
    const rec = recorder();
    const deps = { fetchFn, nowSeconds: clock.now, cache, ...rec };

    await resolveDidWeb(DID, deps);
    clock.advance(100);
    const doc = await resolveDidWeb(DID, deps);

    expect(doc.id).toBe(DID);
    expect(calls()).toBe(1);
    expect(rec.states).toEqual(['cold', 'hot']);
  });

  it('TTL 切れ後の解決は warm で再取得する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch();
    const rec = recorder();
    const deps = { fetchFn, nowSeconds: clock.now, cache, ...rec };

    await resolveDidWeb(DID, deps);
    clock.advance(DID_WEB_CACHE_MAX_TTL_SECONDS + 1);
    await resolveDidWeb(DID, deps);

    expect(calls()).toBe(2);
    expect(rec.states).toEqual(['cold', 'warm']);
  });

  it('cache を渡さない場合は毎回 cold で取得する（関数は状態を持たない）', async () => {
    const { fetchFn, calls } = okFetch();
    const rec = recorder();

    await resolveDidWeb(DID, { fetchFn, ...rec });
    await resolveDidWeb(DID, { fetchFn, ...rec });

    expect(calls()).toBe(2);
    expect(rec.states).toEqual(['cold', 'cold']);
  });

  it('MethodWeb は既定でインスタンス専用キャッシュを持つ', async () => {
    const clock = fixedClock();
    const { fetchFn, calls } = okFetch();
    const method = new MethodWeb({ fetchFn, nowSeconds: clock.now });

    await method.resolve(DID);
    await method.resolve(DID);
    expect(calls()).toBe(1);

    // 別インスタンスはキャッシュを共有しない。
    await new MethodWeb({ fetchFn, nowSeconds: clock.now }).resolve(DID);
    expect(calls()).toBe(2);
  });

  it('MethodWeb に共有キャッシュを渡すとインスタンス間で共有される', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch();

    await new MethodWeb({ fetchFn, nowSeconds: clock.now, cache }).resolve(DID);
    await new MethodWeb({ fetchFn, nowSeconds: clock.now, cache }).resolve(DID);

    expect(calls()).toBe(1);
  });
});

describe('did:web キャッシュ — Cache-Control と TTL 上限', () => {
  it('過大な max-age は 600 秒でキャップする（配信側の設定は拒否せず切り詰める）', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch('max-age=99999');
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await resolveDidWeb(DID, deps);
    clock.advance(DID_WEB_CACHE_MAX_TTL_SECONDS - 1);
    await resolveDidWeb(DID, deps);
    expect(calls()).toBe(1);

    clock.advance(2); // 通算 601 秒。600 秒キャップを越える。
    await resolveDidWeb(DID, deps);
    expect(calls()).toBe(2);
  });

  it('上限より短い max-age はそのまま尊重する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch('max-age=60');
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await resolveDidWeb(DID, deps);
    clock.advance(59);
    await resolveDidWeb(DID, deps);
    expect(calls()).toBe(1);

    clock.advance(2); // 通算 61 秒。
    await resolveDidWeb(DID, deps);
    expect(calls()).toBe(2);
  });

  it('Cache-Control 無しは上限 600 秒を TTL として採用する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch();
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await resolveDidWeb(DID, deps);
    clock.advance(DID_WEB_CACHE_MAX_TTL_SECONDS - 1);
    await resolveDidWeb(DID, deps);
    expect(calls()).toBe(1);

    clock.advance(1); // 通算 600 秒。境界は失効側。
    await resolveDidWeb(DID, deps);
    expect(calls()).toBe(2);
  });

  it('no-store は毎回再取得し、キャッシュに残さない', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch('no-store');
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await resolveDidWeb(DID, deps);
    await resolveDidWeb(DID, deps);
    await resolveDidWeb(DID, deps);

    expect(calls()).toBe(3);
    expect(cache.size).toBe(0);
  });

  it('no-cache も毎回再取得する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = okFetch('no-cache');
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    await resolveDidWeb(DID, deps);
    await resolveDidWeb(DID, deps);

    expect(calls()).toBe(2);
  });
});

describe('did:web キャッシュ — 保持量の上限', () => {
  /** 本文長が `padding` 文字ぶん膨らんだ DID Document を返す fetch。 */
  function paddedFetch(padding: number) {
    return countingFetch(() =>
      mockResponse({
        body: JSON.stringify({ ...SAMPLE_DOC, padding: 'x'.repeat(padding) }),
        contentType: 'application/did+json',
      }),
    );
  }

  it('1 件の上限を超える本文はキャッシュせず、解決自体は成功する', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now);
    const { fetchFn, calls } = paddedFetch(DID_WEB_CACHE_MAX_ENTRY_LENGTH);
    const deps = { fetchFn, nowSeconds: clock.now, cache };

    expect((await resolveDidWeb(DID, deps)).id).toBe(DID);
    await resolveDidWeb(DID, deps);

    expect(calls()).toBe(2);
    expect(cache.size).toBe(0);
  });

  it('異なる did:web を並べても保持本文長の合計は上限を超えない', async () => {
    const clock = fixedClock();
    const cache = createDidWebCache(clock.now, 10_000);
    const padding = DID_WEB_CACHE_MAX_ENTRY_LENGTH - 1_000;
    const entryCount = 3 * Math.ceil(DID_WEB_CACHE_MAX_TOTAL_LENGTH / padding);

    for (let index = 0; index < entryCount; index += 1) {
      const did = `did:web:host${index}.example.com`;
      const { fetchFn } = countingFetch(() =>
        mockResponse({
          body: JSON.stringify({ ...SAMPLE_DOC, id: did, padding: 'x'.repeat(padding) }),
          contentType: 'application/did+json',
          url: `https://host${index}.example.com/.well-known/did.json`,
        }),
      );
      await resolveDidWeb(did, { fetchFn, nowSeconds: clock.now, cache });
    }

    expect(cache.size).toBeLessThanOrEqual(DID_WEB_CACHE_MAX_TOTAL_LENGTH / padding);
    expect(cache.size).toBeGreaterThan(0);
  });
});
