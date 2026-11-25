/**
 * 注入された現在時刻が非有限（NaN / ±Infinity）でも期限検証・キャッシュ TTL が fail-open しないことの
 * 回帰テスト。
 *
 * `now >= exp` / `iat > now + skew` / `now - storedAt >= ttl` は `now` が NaN だと常に `false` になり、
 * 期限切れ・未発効・未来 iat・TTL 切れをそのまま通す。修正前はいずれの検証も例外を出さず、
 * このテストが落ちる。型（`number`）では排除できないため、時刻比較の入口で拒否する（4015）。
 */

import { describe, expect, it } from 'bun:test';
import { assertFiniteClock } from '../../../cache/system-clock.js';
import { createTtlCache } from '../../../cache/ttl-cache.js';
import { UrlKeyedTtlCache } from '../../../cache/url-keyed-ttl-cache.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ChainVerificationCache } from '../../chain/cache.js';
import type { ChainVerificationResult } from '../../chain/types.js';
import { isExpiredAt } from '../../presentation/credential-entry/entry-result.js';
import { assertTimeClaims } from '../../time-claims.js';

const NON_FINITE = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY] as const;
const CLOCK_INVALID = new VericertsError(ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
const N = 1_767_225_600;

describe('assertFiniteClock', () => {
  it('有限数はそのまま返す', () => {
    expect(assertFiniteClock(N)).toBe(N);
    expect(assertFiniteClock(0)).toBe(0);
  });

  for (const bad of NON_FINITE) {
    it(`${bad} は 4015 で拒否する`, () => {
      expect(() => assertFiniteClock(bad)).toThrow(CLOCK_INVALID);
    });
  }

  it('数値でない値（型の無い JS 呼び出し）も 4015 で拒否する', () => {
    expect(() => assertFiniteClock('123' as unknown as number)).toThrow(CLOCK_INVALID);
    expect(() => assertFiniteClock(null as unknown as number)).toThrow(CLOCK_INVALID);
  });
});

describe('assertTimeClaims: 非有限の nowSeconds / skewSeconds は fail-closed（4015）', () => {
  for (const bad of NON_FINITE) {
    it(`nowSeconds = ${bad}: 期限切れ payload を通さない`, () => {
      expect(() => assertTimeClaims({ exp: N - 1000 }, N, 0)).toThrow(
        new VericertsError(ErrorCodes.VC_EXPIRED),
      );
      expect(() => assertTimeClaims({ exp: N - 1000 }, bad, 0)).toThrow(CLOCK_INVALID);
    });

    it(`nowSeconds = ${bad}: 未発効（nbf）payload を通さない`, () => {
      expect(() => assertTimeClaims({ nbf: N + 1000 }, N, 0)).toThrow(
        new VericertsError(ErrorCodes.VC_NOT_YET_VALID),
      );
      expect(() => assertTimeClaims({ nbf: N + 1000 }, bad, 0)).toThrow(CLOCK_INVALID);
    });

    it(`nowSeconds = ${bad}: 未来 iat（時計進み）payload を通さない`, () => {
      expect(() => assertTimeClaims({ iat: N + 1000 }, N, 30)).toThrow(
        new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
      );
      expect(() => assertTimeClaims({ iat: N + 1000 }, bad, 30)).toThrow(CLOCK_INVALID);
    });

    it(`skewSeconds = ${bad}: 窓を壊して期限切れを通さない`, () => {
      expect(() => assertTimeClaims({ exp: N - 1000 }, N, bad)).toThrow(CLOCK_INVALID);
    });

    it(`nowSeconds = ${bad}: 時刻クレームが無い payload でも時計不正を検出する`, () => {
      expect(() => assertTimeClaims({}, bad, 0)).toThrow(CLOCK_INVALID);
    });
  }

  it('有限値の従来挙動は変わらない（期間内は通る）', () => {
    expect(() => assertTimeClaims({ iat: N, nbf: N - 10, exp: N + 10 }, N, 0)).not.toThrow();
  });
});

describe('isExpiredAt: 非有限の nowSeconds は失効扱い（fail-closed）', () => {
  it('有限時刻の従来挙動（exp 超過のみ失効）', () => {
    expect(isExpiredAt({ exp: N - 1 }, N)).toBe(true);
    expect(isExpiredAt({ exp: N + 1 }, N)).toBe(false);
    expect(isExpiredAt({}, N)).toBe(false);
  });

  for (const bad of NON_FINITE) {
    it(`nowSeconds = ${bad}: exp を持つ payload を「有効」と表示しない`, () => {
      expect(isExpiredAt({ exp: N + 1_000_000 }, bad)).toBe(true);
    });
  }
});

describe('ChainVerificationCache: 非有限の now で TTL 切れ結果を再利用しない', () => {
  const result: ChainVerificationResult = {
    vcId: 'urn:uuid:vc-1',
    valid: true,
    depth: 0,
    chain: [],
  };

  for (const bad of NON_FINITE) {
    it(`now = ${bad}: 保存済みの結果を返さない（miss）`, () => {
      const cache = new ChainVerificationCache(1_000);
      cache.set('k', result, 0);
      // 有限時刻では TTL 内なら hit、TTL 超過なら miss（従来挙動）。
      expect(cache.get('k', 500)).toBe(result);
      expect(cache.get('k', 5_000)).toBeUndefined();
      // 修正前は NaN で `now - storedAt >= ttl` が常に false になり、期限切れ結果を返し続けた。
      const fresh = new ChainVerificationCache(1_000);
      fresh.set('k', result, 0);
      expect(fresh.get('k', bad)).toBeUndefined();
    });
  }
});

describe('UrlKeyedTtlCache: 非有限の now で TTL 切れ値を再利用しない', () => {
  for (const bad of NON_FINITE) {
    it(`now = ${bad}: 保存済みの値を返さない（miss）`, () => {
      const cache = new UrlKeyedTtlCache<string>(1_000);
      cache.set('https://example.com/a', 'v', 0);
      expect(cache.get('https://example.com/a', 500)).toBe('v');
      expect(cache.get('https://example.com/a', bad)).toBeUndefined();
    });
  }
});

describe('createTtlCache: 非有限の時刻は 4015（NaN 期限のエントリを作らない）', () => {
  it('注入クロックが NaN を返すと get / set とも 4015', () => {
    const good = createTtlCache<string>({ nowSeconds: () => N, maxTtlSeconds: 300 });
    good.set('k', 'v', 60);
    expect(good.get('k')).toEqual({ value: 'v', expired: false });

    const broken = createTtlCache<string>({ nowSeconds: () => Number.NaN, maxTtlSeconds: 300 });
    // 修正前は `NaN + ttl` の期限で格納され、以後 `now >= NaN` が常に false（= 永久に新鮮）になった。
    expect(() => broken.set('k', 'v', 60)).toThrow(CLOCK_INVALID);
    expect(() => broken.get('k')).not.toThrow(); // 未格納キーは時計を評価しない
  });

  it('明示 nowSeconds に NaN を渡した get は 4015（期限切れ値を新鮮と返さない）', () => {
    const cache = createTtlCache<string>({ nowSeconds: () => N, maxTtlSeconds: 300 });
    cache.set('k', 'v', 60);
    expect(cache.get('k', N + 1_000)?.expired).toBe(true);
    expect(() => cache.get('k', Number.NaN)).toThrow(CLOCK_INVALID);
  });
});
