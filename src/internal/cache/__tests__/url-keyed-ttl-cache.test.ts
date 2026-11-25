/**
 * URL キー・固定 TTL・FIFO 上限キャッシュのプリミティブ検証。
 *
 * Type Metadata 経路と `credentialSchema` 経路に重複していた実装を共有クラスへ抽出したため、
 * 抽出後も挙動が同一であることをこのファイルで直接固定する。時刻は引数で注入して決定的に検証する。
 * 検証対象: 格納・命中・失効境界（`now - storedAt >= ttlMs`）・`clear`・`maxEntries` の FIFO 追い出し・
 * 同一キー再格納による挿入順の更新。
 */

import { describe, expect, it } from 'bun:test';
import { UrlKeyedTtlCache } from '../url-keyed-ttl-cache.js';

/** 固定時計（テスト内で手動で進める。単位はミリ秒）。 */
function fixedClock(start: number): { now: () => number; advance: (ms: number) => void } {
  let current = start;
  return {
    now: () => current,
    advance: (ms: number) => {
      current += ms;
    },
  };
}

describe('UrlKeyedTtlCache の格納と命中', () => {
  it('格納した値を TTL 内では命中として返す', () => {
    const clock = fixedClock(1000);
    const cache = new UrlKeyedTtlCache<string>(60_000);
    cache.set('https://issuer.example/a.json', 'doc', clock.now());
    expect(cache.get('https://issuer.example/a.json', clock.now())).toBe('doc');
  });

  it('未登録の URL は undefined を返す', () => {
    const cache = new UrlKeyedTtlCache<string>(60_000);
    expect(cache.get('https://issuer.example/missing.json', 0)).toBeUndefined();
  });

  it('キーは URL 完全一致のみ（末尾スラッシュ違いは別エントリ）', () => {
    const cache = new UrlKeyedTtlCache<string>(60_000);
    cache.set('https://issuer.example/a', 'doc', 0);
    expect(cache.get('https://issuer.example/a/', 0)).toBeUndefined();
  });

  it('同一キーの再格納は最新の値で上書きする', () => {
    const cache = new UrlKeyedTtlCache<string>(60_000);
    cache.set('https://issuer.example/a.json', 'old', 0);
    cache.set('https://issuer.example/a.json', 'new', 0);
    expect(cache.get('https://issuer.example/a.json', 0)).toBe('new');
  });
});

describe('UrlKeyedTtlCache の失効', () => {
  it('TTL 経過ちょうどで失効する（境界は失効側）', () => {
    const clock = fixedClock(0);
    const cache = new UrlKeyedTtlCache<string>(60_000);
    cache.set('https://issuer.example/a.json', 'doc', clock.now());
    clock.advance(59_999);
    expect(cache.get('https://issuer.example/a.json', clock.now())).toBe('doc');
    clock.advance(1); // now - storedAt === ttlMs
    expect(cache.get('https://issuer.example/a.json', clock.now())).toBeUndefined();
  });

  it('失効エントリは get 時に削除され、時計を戻しても復活しない', () => {
    const cache = new UrlKeyedTtlCache<string>(60_000);
    cache.set('https://issuer.example/a.json', 'doc', 0);
    expect(cache.get('https://issuer.example/a.json', 60_000)).toBeUndefined();
    expect(cache.get('https://issuer.example/a.json', 0)).toBeUndefined();
  });

  it('再格納すれば TTL は記録時刻から数え直す', () => {
    const cache = new UrlKeyedTtlCache<string>(60_000);
    cache.set('https://issuer.example/a.json', 'doc', 0);
    cache.set('https://issuer.example/a.json', 'doc2', 50_000);
    expect(cache.get('https://issuer.example/a.json', 100_000)).toBe('doc2');
  });

  it('clear で全エントリを破棄する', () => {
    const cache = new UrlKeyedTtlCache<string>(60_000);
    cache.set('https://issuer.example/a.json', '1', 0);
    cache.set('https://issuer.example/b.json', '2', 0);
    cache.clear();
    expect(cache.get('https://issuer.example/a.json', 0)).toBeUndefined();
    expect(cache.get('https://issuer.example/b.json', 0)).toBeUndefined();
  });
});

describe('UrlKeyedTtlCache のメモリ上界', () => {
  it('maxEntries を超えたら挿入順に古いものから捨てる（FIFO）', () => {
    const cache = new UrlKeyedTtlCache<number>(60_000, 3);
    for (let i = 0; i < 10; i += 1) {
      cache.set(`https://issuer.example/${i}.json`, i, 0);
    }
    expect(cache.get('https://issuer.example/0.json', 0)).toBeUndefined();
    expect(cache.get('https://issuer.example/6.json', 0)).toBeUndefined();
    expect(cache.get('https://issuer.example/7.json', 0)).toBe(7);
    expect(cache.get('https://issuer.example/9.json', 0)).toBe(9);
  });

  it('同一キーの再格納では件数が増えない（上限内のキーが追い出されない）', () => {
    const cache = new UrlKeyedTtlCache<number>(60_000, 2);
    cache.set('https://issuer.example/a.json', 1, 0);
    cache.set('https://issuer.example/a.json', 2, 0);
    cache.set('https://issuer.example/b.json', 3, 0);
    expect(cache.get('https://issuer.example/a.json', 0)).toBe(2);
    expect(cache.get('https://issuer.example/b.json', 0)).toBe(3);
  });

  it('再格納したキーは挿入順の最後尾に移る（次の追い出し対象にならない）', () => {
    const cache = new UrlKeyedTtlCache<number>(60_000, 2);
    cache.set('https://issuer.example/a.json', 1, 0);
    cache.set('https://issuer.example/b.json', 2, 0);
    cache.set('https://issuer.example/a.json', 3, 0); // a が最新になる
    cache.set('https://issuer.example/c.json', 4, 0); // 追い出されるのは b
    expect(cache.get('https://issuer.example/b.json', 0)).toBeUndefined();
    expect(cache.get('https://issuer.example/a.json', 0)).toBe(3);
    expect(cache.get('https://issuer.example/c.json', 0)).toBe(4);
  });
});

describe('UrlKeyedTtlCache の重み上限', () => {
  const big = (chars: number) => ({ body: 'x'.repeat(chars) });

  it('1 件の重みが上限を超える値は格納しない（同じ URL の古い値も消す）', () => {
    const cache = new UrlKeyedTtlCache<unknown>(60_000, 256, 1000, 10_000);
    cache.set('https://a.example/', big(10), 0);
    cache.set('https://a.example/', big(2000), 0);
    expect(cache.get('https://a.example/', 0)).toBeUndefined();
  });

  it('重みの合計が上限を超えたら古い順に追い出す（件数上限の手前でも）', () => {
    const cache = new UrlKeyedTtlCache<unknown>(60_000, 256, 1000, 2500);
    for (let i = 0; i < 5; i++) cache.set(`https://a.example/${i}`, big(900), 0);
    // 1 件 ≈ 911 文字、合計 2500 までなので保持できるのは直近 2 件。
    expect(
      [0, 1, 2, 3, 4].map((i) => cache.get(`https://a.example/${i}`, 0) !== undefined),
    ).toEqual([false, false, false, true, true]);
  });

  it('既定では 1 MiB × 256 件を投入しても保持量は合計上限（2 MiB）に収まる', () => {
    const cache = new UrlKeyedTtlCache<unknown>(60_000);
    const doc = big(1024 * 1024);
    for (let i = 0; i < 256; i++) cache.set(`https://a.example/${i}`, doc, 0);
    let kept = 0;
    for (let i = 0; i < 256; i++) if (cache.get(`https://a.example/${i}`, 0) !== undefined) kept++;
    expect(kept).toBe(0);
  });

  it('上限内の小さな文書は従来どおり件数上限まで保持する', () => {
    const cache = new UrlKeyedTtlCache<unknown>(60_000, 3);
    for (let i = 0; i < 5; i++) cache.set(`https://a.example/${i}`, { n: i }, 0);
    expect(
      [0, 1, 2, 3, 4].map((i) => cache.get(`https://a.example/${i}`, 0) !== undefined),
    ).toEqual([false, false, true, true, true]);
  });

  it('JSON にできない値（循環参照）は格納しない', () => {
    const cache = new UrlKeyedTtlCache<unknown>(60_000);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    cache.set('https://a.example/', cyclic, 0);
    expect(cache.get('https://a.example/', 0)).toBeUndefined();
  });

  it('clear() で重みの合計も 0 に戻る', () => {
    const cache = new UrlKeyedTtlCache<unknown>(60_000, 256, 1000, 1000);
    cache.set('https://a.example/0', big(900), 0);
    cache.clear();
    cache.set('https://a.example/1', big(900), 0);
    expect(cache.get('https://a.example/1', 0)).toBeDefined();
  });
});
