/**
 * `parseJsonWithoutPrototype` の単体テスト。
 *
 * 検証内容:
 * - 結果（入れ子・配列要素を含む）のプロトタイプが `null` であること
 * - `Object.prototype` のデータ汚染・アクセサ汚染のいずれも読み出せないこと
 * - 配列 / プリミティブ / `null` の形と、`JSON.stringify` / `Object.keys` / スプレッド /
 *   分割代入の互換性が保たれること
 * - パース失敗を正規化せず `SyntaxError` のまま送出すること（エラーコード正規化は各サイトの責務）
 */

import { describe, expect, it } from 'bun:test';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../prototype-pollution.fixtures.js';

describe('parseJsonWithoutPrototype: プロトタイプの除去', () => {
  it('トップレベルのオブジェクトのプロトタイプが null になる', () => {
    const parsed = parseJsonWithoutPrototype('{"a":1}');
    expect(Object.getPrototypeOf(parsed as object)).toBeNull();
  });

  it('入れ子のオブジェクトも再帰的に null プロトタイプになる', () => {
    const parsed = parseJsonWithoutPrototype('{"outer":{"inner":{"deep":1}}}') as {
      outer: { inner: object };
    };
    expect(Object.getPrototypeOf(parsed.outer)).toBeNull();
    expect(Object.getPrototypeOf(parsed.outer.inner)).toBeNull();
  });

  it('配列は配列のまま保たれ、要素のオブジェクトは null プロトタイプになる', () => {
    const parsed = parseJsonWithoutPrototype('{"list":[{"a":1},"s",2,null]}') as {
      list: unknown[];
    };
    expect(Array.isArray(parsed.list)).toBe(true);
    expect(Object.getPrototypeOf(parsed.list[0] as object)).toBeNull();
    expect(parsed.list[1]).toBe('s');
    expect(parsed.list[2]).toBe(2);
    expect(parsed.list[3]).toBeNull();
  });

  it('トップレベルが配列でも配列のまま返る', () => {
    const parsed = parseJsonWithoutPrototype('[{"a":1}]');
    expect(Array.isArray(parsed)).toBe(true);
  });

  it('プリミティブと null はそのまま返る', () => {
    expect(parseJsonWithoutPrototype('"s"')).toBe('s');
    expect(parseJsonWithoutPrototype('1')).toBe(1);
    expect(parseJsonWithoutPrototype('true')).toBe(true);
    expect(parseJsonWithoutPrototype('null')).toBeNull();
  });
});

describe('parseJsonWithoutPrototype: 汚染下での読み取り', () => {
  it('データ汚染を継承しない（当該キーを持たない JSON で undefined）', () => {
    const value = withPollutedPrototype({ credential: 'ATTACKER_VC' }, () => {
      const parsed = parseJsonWithoutPrototype('{}') as Record<string, unknown>;
      return parsed.credential;
    });
    expect(value).toBeUndefined();
  });

  it('入れ子のオブジェクトもデータ汚染を継承しない', () => {
    const value = withPollutedPrototype({ jwk: 'ATTACKER_JWK' }, () => {
      const parsed = parseJsonWithoutPrototype('{"cnf":{}}') as {
        cnf: Record<string, unknown>;
      };
      return parsed.cnf.jwk;
    });
    expect(value).toBeUndefined();
  });

  it('アクセサ汚染を継承せず、2 度読みしても値が食い違わない（TOCTOU 不成立）', () => {
    let calls = 0;
    const reads = withPollutedPrototypeAccessor(
      {
        sneaky: () => {
          calls += 1;
          return `value-${calls}`;
        },
      },
      () => {
        const parsed = parseJsonWithoutPrototype('{}') as Record<string, unknown>;
        return [parsed.sneaky, parsed.sneaky];
      },
    );
    expect(reads[0]).toBeUndefined();
    expect(reads[1]).toBeUndefined();
    // getter がそもそも呼ばれない（鎖を辿らないため）。
    expect(calls).toBe(0);
  });

  it('自身のプロパティは汚染下でも正しく読める', () => {
    const value = withPollutedPrototype({ credential: 'ATTACKER_VC' }, () => {
      const parsed = parseJsonWithoutPrototype('{"credential":"LEGIT_VC"}') as Record<
        string,
        unknown
      >;
      return parsed.credential;
    });
    expect(value).toBe('LEGIT_VC');
  });
});

describe('parseJsonWithoutPrototype: ペイロード自体の __proto__ キー', () => {
  // `Object.create(null)` をターゲットにした `Object.assign` は `Object.prototype.__proto__` の
  // setter を経由しないため、`__proto__` は own データプロパティとして保持され `Object.prototype`
  // は汚染されない。コピー方式を変える改修（スプレッド以外・`for...in` 代入等）で静かに壊れうる
  // ので固定する。
  it('トップレベルの __proto__ キーで Object.prototype を汚染しない', () => {
    parseJsonWithoutPrototype('{"__proto__":{"polluted":1}}');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('__proto__ を own プロパティとして保持し、プロトタイプは差し替わらない', () => {
    const parsed = parseJsonWithoutPrototype('{"__proto__":{"polluted":1}}') as object;
    expect(Object.hasOwn(parsed, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(
      (Object.getOwnPropertyDescriptor(parsed, '__proto__')?.value as { polluted: number })
        .polluted,
    ).toBe(1);
  });

  it('入れ子の __proto__ キーでも Object.prototype を汚染しない', () => {
    const parsed = parseJsonWithoutPrototype('{"a":{"__proto__":{"polluted":1}}}') as {
      a: object;
    };
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.hasOwn(parsed.a, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(parsed.a)).toBeNull();
  });
});

describe('parseJsonWithoutPrototype: 互換性', () => {
  const json = '{"a":1,"b":{"c":[1,2]},"d":null}';

  it('JSON.stringify でラウンドトリップできる', () => {
    expect(JSON.stringify(parseJsonWithoutPrototype(json))).toBe(json);
  });

  it('Object.keys / Object.hasOwn / スプレッド / 分割代入が通常どおり動く', () => {
    const parsed = parseJsonWithoutPrototype(json) as Record<string, unknown>;
    expect(Object.keys(parsed)).toEqual(['a', 'b', 'd']);
    expect(Object.hasOwn(parsed, 'a')).toBe(true);
    expect(Object.hasOwn(parsed, 'zzz')).toBe(false);
    expect({ ...parsed }).toEqual({ a: 1, b: { c: [1, 2] }, d: null });
    const { a } = parsed as { a: number };
    expect(a).toBe(1);
  });

  it('toEqual / toStrictEqual / toMatchObject が通常どおり通る', () => {
    const parsed = parseJsonWithoutPrototype('{"a":1,"b":{"c":2}}');
    expect(parsed).toEqual({ a: 1, b: { c: 2 } });
    expect(parsed).toStrictEqual({ a: 1, b: { c: 2 } });
    expect(parsed).toMatchObject({ b: { c: 2 } });
  });
});

describe('parseJsonWithoutPrototype: エラー', () => {
  it('パース失敗は正規化せず SyntaxError のまま投げる（各サイトの catch が正規化する）', () => {
    expect(() => parseJsonWithoutPrototype('{')).toThrow(SyntaxError);
  });
});
