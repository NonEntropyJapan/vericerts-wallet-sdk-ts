/**
 * 汎用 TTL キャッシュのプリミティブ検証。
 *
 * 時計は注入して決定的に検証する。検証対象:
 * - `parseMaxAgeSeconds`: issuer 側から移設した後も挙動が同一であること。
 * - `resolveMaxTtlSeconds`: 上限の緩和は拒否（3002）、厳格化は許可。
 * - `createTtlCache`: 格納・命中・失効境界・`ttlSeconds: 0`・negative cache 30 秒固定・
 *   成功時の negative 破棄・`maxEntries` による上界。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../errors.js';
import {
  createTtlCache,
  NEGATIVE_CACHE_TTL_SECONDS,
  parseMaxAgeSeconds,
  resolveMaxTtlSeconds,
} from '../ttl-cache.js';

/** 例外が指定コードの VericertsError であることを検証する。 */
function expectThrowsCode(fn: () => unknown, code: ErrorCode): void {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

/** 固定時計（テスト内で手動で進める）。 */
function fixedClock(start: number): { now: () => number; advance: (seconds: number) => void } {
  let current = start;
  return {
    now: () => current,
    advance: (seconds: number) => {
      current += seconds;
    },
  };
}

describe('parseMaxAgeSeconds（issuer からの移設後も同一挙動）', () => {
  it('max-age を秒数として取り出す', () => {
    expect(parseMaxAgeSeconds('max-age=120')).toBe(120);
    expect(parseMaxAgeSeconds('public, max-age=300, must-revalidate')).toBe(300);
    expect(parseMaxAgeSeconds('MAX-AGE = "45"')).toBe(45);
  });

  it('no-store / no-cache は 0（キャッシュ不可）', () => {
    expect(parseMaxAgeSeconds('no-store')).toBe(0);
    expect(parseMaxAgeSeconds('no-cache, max-age=600')).toBe(0);
  });

  it('未設定 / max-age 無し / 数値でない場合は undefined', () => {
    expect(parseMaxAgeSeconds(null)).toBeUndefined();
    expect(parseMaxAgeSeconds(undefined)).toBeUndefined();
    expect(parseMaxAgeSeconds('public')).toBeUndefined();
    expect(parseMaxAgeSeconds('max-age=abc')).toBeUndefined();
  });

  it('引用符の対応が崩れた max-age は undefined', () => {
    // 閉じ引用符が無い（開き引用符のみ）
    expect(parseMaxAgeSeconds('max-age="600')).toBeUndefined();
    // 開き引用符が無い（閉じ引用符のみ）
    expect(parseMaxAgeSeconds('max-age=600"')).toBeUndefined();
  });
});

describe('resolveMaxTtlSeconds', () => {
  it('未指定なら上限をそのまま採用する', () => {
    expect(resolveMaxTtlSeconds(undefined, 600)).toBe(600);
  });

  it('上限と等しい値は許可する', () => {
    expect(resolveMaxTtlSeconds(600, 600)).toBe(600);
  });

  it('上限より厳しい値（0 を含む）は許可する', () => {
    expect(resolveMaxTtlSeconds(60, 600)).toBe(60);
    expect(resolveMaxTtlSeconds(0, 600)).toBe(0);
  });

  it('上限を緩める設定は 3002 で拒否する（切り詰めではなく拒否）', () => {
    expectThrowsCode(() => resolveMaxTtlSeconds(601, 600), ErrorCodes.VC_SCHEMA_INVALID);
    expectThrowsCode(() => resolveMaxTtlSeconds(86_400, 600), ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('負値 / 非整数 / NaN / Infinity は 3002 で拒否する', () => {
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expectThrowsCode(() => resolveMaxTtlSeconds(bad, 600), ErrorCodes.VC_SCHEMA_INVALID);
    }
  });
});

describe('createTtlCache 正エントリ', () => {
  it('格納した値を TTL 内では命中として返す', () => {
    const clock = fixedClock(1000);
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: clock.now });
    cache.set('k', 'v', 60);
    expect(cache.get('k')).toEqual({ value: 'v', expired: false });
    expect(cache.size).toBe(1);
  });

  it('失効時刻ちょうどで失効扱いになる（境界は失効側）', () => {
    const clock = fixedClock(1000);
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: clock.now });
    cache.set('k', 'v', 60);
    clock.advance(59);
    expect(cache.get('k')?.expired).toBe(false);
    clock.advance(1); // now === expiresAt
    expect(cache.get('k')?.expired).toBe(true);
  });

  it('失効後もエントリ自体は返す（warm を観測できるようにするため）', () => {
    const clock = fixedClock(0);
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: clock.now });
    cache.set('k', 'v', 10);
    clock.advance(100);
    expect(cache.get('k')).toEqual({ value: 'v', expired: true });
  });

  it('ttlSeconds: 0 は格納せず、既存の値も消す（no-store / no-cache 相当）', () => {
    const clock = fixedClock(0);
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: clock.now });
    cache.set('k', 'v', 60);
    expect(cache.size).toBe(1);
    cache.set('k', 'v2', 0);
    expect(cache.get('k')).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it('キャッシュ自身の TTL 上限を超える TTL は上限で切り詰める', () => {
    const clock = fixedClock(0);
    const cache = createTtlCache<string>({ maxTtlSeconds: 60, nowSeconds: clock.now });
    cache.set('k', 'v', 100_000);
    clock.advance(59);
    expect(cache.get('k')?.expired).toBe(false);
    clock.advance(1);
    expect(cache.get('k')?.expired).toBe(true);
  });

  it('未登録キーは undefined を返す', () => {
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: () => 0 });
    expect(cache.get('missing')).toBeUndefined();
  });

  it('delete / clear でエントリを破棄できる', () => {
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: () => 0 });
    cache.set('a', '1', 60);
    cache.set('b', '2', 60);
    cache.delete('a');
    expect(cache.get('a')).toBeUndefined();
    expect(cache.size).toBe(1);
    cache.clear();
    expect(cache.size).toBe(0);
  });

  it('TTL が非負整数でない場合は 3002 を投げる', () => {
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: () => 0 });
    expectThrowsCode(() => cache.set('k', 'v', -1), ErrorCodes.VC_SCHEMA_INVALID);
    expectThrowsCode(() => cache.set('k', 'v', 1.5), ErrorCodes.VC_SCHEMA_INVALID);
  });
});

describe('createTtlCache negative エントリ', () => {
  it('記憶した失敗を 30 秒間返し、ちょうど 30 秒で失効する', () => {
    const clock = fixedClock(0);
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: clock.now });
    const failure = new VericertsError(ErrorCodes.DID_NOT_FOUND);
    cache.setNegative('k', failure);
    expect(cache.getNegative('k')).toBe(failure);
    clock.advance(NEGATIVE_CACHE_TTL_SECONDS - 1);
    expect(cache.getNegative('k')).toBe(failure);
    clock.advance(1); // now === expiresAt
    expect(cache.getNegative('k')).toBeUndefined();
  });

  it('negative TTL は 30 秒固定で、キャッシュの TTL 上限に影響されない', () => {
    const clock = fixedClock(0);
    const cache = createTtlCache<string>({ maxTtlSeconds: 5, nowSeconds: clock.now });
    cache.setNegative('k', new VericertsError(ErrorCodes.DID_NOT_FOUND));
    clock.advance(29);
    expect(cache.getNegative('k')).toBeDefined();
  });

  it('取得成功（set）は同キーの negative エントリを破棄する', () => {
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: () => 0 });
    cache.setNegative('k', new VericertsError(ErrorCodes.DID_NOT_FOUND));
    cache.set('k', 'v', 60);
    expect(cache.getNegative('k')).toBeUndefined();
    expect(cache.get('k')?.value).toBe('v');
  });

  it('TTL 0（no-store）の取得成功でも negative エントリは破棄する', () => {
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: () => 0 });
    cache.setNegative('k', new VericertsError(ErrorCodes.DID_NOT_FOUND));
    cache.set('k', 'v', 0);
    expect(cache.getNegative('k')).toBeUndefined();
  });

  it('正エントリと negative エントリは独立している（size は正のみ数える）', () => {
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: () => 0 });
    cache.setNegative('k', new VericertsError(ErrorCodes.DID_NOT_FOUND));
    expect(cache.size).toBe(0);
    expect(cache.get('k')).toBeUndefined();
  });

  it('delete は negative エントリも消す', () => {
    const cache = createTtlCache<string>({ maxTtlSeconds: 600, nowSeconds: () => 0 });
    cache.setNegative('k', new VericertsError(ErrorCodes.DID_NOT_FOUND));
    cache.delete('k');
    expect(cache.getNegative('k')).toBeUndefined();
  });
});

describe('createTtlCache のメモリ上界', () => {
  it('maxEntries を超えたら古い順に捨てる', () => {
    const cache = createTtlCache<number>({
      maxTtlSeconds: 600,
      nowSeconds: () => 0,
      maxEntries: 3,
    });
    for (let i = 0; i < 10; i += 1) {
      cache.set(`k${i}`, i, 60);
    }
    expect(cache.size).toBe(3);
    expect(cache.get('k0')).toBeUndefined();
    expect(cache.get('k6')).toBeUndefined();
    expect(cache.get('k9')?.value).toBe(9);
    expect(cache.get('k7')?.value).toBe(7);
  });

  it('同一キーの再格納では件数が増えず、最新の値になる', () => {
    const cache = createTtlCache<number>({
      maxTtlSeconds: 600,
      nowSeconds: () => 0,
      maxEntries: 2,
    });
    cache.set('a', 1, 60);
    cache.set('a', 2, 60);
    expect(cache.size).toBe(1);
    expect(cache.get('a')?.value).toBe(2);
  });

  it('negative エントリも maxEntries で上界を持つ', () => {
    const cache = createTtlCache<number>({
      maxTtlSeconds: 600,
      nowSeconds: () => 0,
      maxEntries: 2,
    });
    for (let i = 0; i < 5; i += 1) {
      cache.setNegative(`k${i}`, new VericertsError(ErrorCodes.DID_NOT_FOUND));
    }
    expect(cache.getNegative('k0')).toBeUndefined();
    expect(cache.getNegative('k4')).toBeDefined();
    expect(cache.getNegative('k3')).toBeDefined();
  });
});

describe('createTtlCache: maxTotalWeight', () => {
  const opts = { maxTtlSeconds: 600, maxTotalWeight: 10 };

  it('重みの合計が上限を超えると古い順に捨てる', () => {
    const cache = createTtlCache<string>({ ...opts, nowSeconds: () => 0 });
    cache.set('a', 'A', 60, undefined, 4);
    cache.set('b', 'B', 60, undefined, 4);
    cache.set('c', 'C', 60, undefined, 4);

    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')?.value).toBe('B');
    expect(cache.get('c')?.value).toBe('C');
  });

  it('単独で上限を超える値は格納せず、同キーの古い値も残さない', () => {
    const cache = createTtlCache<string>({ ...opts, nowSeconds: () => 0 });
    cache.set('a', 'A', 60, undefined, 4);
    cache.set('big', 'BIG', 60, undefined, 11);
    cache.set('a', 'A2', 60, undefined, 11);

    expect(cache.get('big')).toBeUndefined();
    expect(cache.get('a')).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it('同キーの上書き・delete・clear で重みの計上が戻る', () => {
    const cache = createTtlCache<string>({ ...opts, nowSeconds: () => 0 });
    cache.set('a', 'A', 60, undefined, 6);
    cache.set('a', 'A2', 60, undefined, 6); // 二重計上なら 12 > 10 で自分自身が追い出される
    expect(cache.get('a')?.value).toBe('A2');

    cache.delete('a');
    cache.set('b', 'B', 60, undefined, 10);
    expect(cache.get('b')?.value).toBe('B');

    cache.clear();
    cache.set('c', 'C', 60, undefined, 10);
    expect(cache.get('c')?.value).toBe('C');
  });

  it('重みを渡さない値（既定 0）は総量に効かない', () => {
    const cache = createTtlCache<string>({ ...opts, nowSeconds: () => 0 });
    for (let index = 0; index < 5; index += 1) {
      cache.set(`k${index}`, 'v', 60);
    }
    expect(cache.size).toBe(5);
  });
});
