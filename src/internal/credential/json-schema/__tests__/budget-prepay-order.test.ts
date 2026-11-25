/**
 * 走査量予算は「高コスト操作の前に前払いし、予算切れ後は評価を継続しない」。
 *
 * 実時間ではなく決定的なカウンタ（`Object.keys` / `JSON.stringify` の呼び出し回数・評価されたスキーマ
 * ノード数・保持された違反メッセージの長さ）で pin する。サイズと件数の比率を変えた複数の形状で確認する。
 */

import { describe, expect, it, setDefaultTimeout, spyOn } from 'bun:test';
import { MAX_ERRORS, MAX_EVALUATIONS, MAX_SCAN_UNITS } from '../internals.js';
import type { JsonSchema, SchemaValidationResult as Result } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

setDefaultTimeout(30_000);

const hasRootBudgetError = (result: Result): boolean =>
  (result.errors ?? []).some((e) => e.path === '' && e.required && e.message.includes('評価量'));

/** `$ref` の読み出し回数（= validateNode が本体を評価した回数）を数えるスキーマノード。 */
function countingNode(counter: { reads: number }, target: object = {}): JsonSchema {
  return new Proxy(target, {
    get(t, key, receiver) {
      if (key === '$ref') {
        counter.reads += 1;
      }
      return Reflect.get(t, key, receiver);
    },
  }) as JsonSchema;
}

/** 添字読み出しを数える配列（`Array.isArray` は `true`）。 */
function countingArray<T>(length: number, make: (i: number) => T) {
  const counter = { reads: 0 };
  const array = new Proxy(
    Array.from({ length }, (_, i) => make(i)),
    {
      get(t, key, receiver) {
        if (typeof key === 'string' && /^\d+$/.test(key)) {
          counter.reads += 1;
        }
        return Reflect.get(t, key, receiver);
      },
    },
  );
  return { array, counter };
}

const objectWithKeys = (count: number): Record<string, unknown> => {
  const instance: Record<string, unknown> = {};
  for (let i = 0; i < count; i += 1) {
    instance[`k${i}`] = 1;
  }
  return instance;
};

describe('validateObject は予算切れ後に評価・キー列挙を継続しない', () => {
  // [キー数 K, allOf の {} の個数 N]。いずれも N × (K + 文字数/8) が MAX_SCAN_UNITS を超える。
  const shapes: [number, number][] = [
    [1_000, 20_000],
    [10_000, 2_000],
    [100_000, 100],
  ];

  for (const [keyCount, branches] of shapes) {
    it(`K=${keyCount} × allOf ${branches} 件: 列挙は 1 回、評価ノードは予算分だけ`, () => {
      const instance = objectWithKeys(keyCount);
      const counter = { reads: 0 };
      const schema = {
        allOf: Array.from({ length: branches }, () => countingNode(counter)),
      } as JsonSchema;
      const keysSpy = spyOn(Object, 'keys');
      let result: Result;
      let enumerations: number;
      try {
        result = validateAgainstSchema(schema, instance);
        enumerations = keysSpy.mock.calls.filter(([target]) => target === instance).length;
      } finally {
        keysSpy.mockRestore();
      }
      expect(result.valid).toBe(false);
      expect(hasRootBudgetError(result)).toBe(true);
      // 修正前は評価ノードの残量（最大 50,000）ぶん O(K) の列挙が繰り返された。
      expect(enumerations).toBe(1);
      // 1 ノードあたり少なくともキー数ぶんを前払いするので、評価されるノードは予算 / K を超えない。
      expect(counter.reads).toBeLessThanOrEqual(Math.ceil(MAX_SCAN_UNITS / keyCount) + 1);
      expect(counter.reads).toBeLessThan(MAX_EVALUATIONS);
    });
  }

  it('予算内の通常のオブジェクトは従来どおり検証される', () => {
    const schema: JsonSchema = {
      type: 'object',
      required: ['a'],
      properties: { a: { type: 'string' } },
      additionalProperties: false,
    };
    expect(validateAgainstSchema(schema, { a: 'x' })).toEqual({ valid: true });
    expect(validateAgainstSchema(schema, { a: 1, b: 2 }).valid).toBe(false);
  });
});

describe('prefixItems はスキーマ側配列長を前払いする', () => {
  // [prefixItems 長 P, $ref 参照数 R]。いずれも P × R が MAX_SCAN_UNITS を超える。
  const shapes: [number, number][] = [
    [1_000, 5_000],
    [100_000, 50],
    [250_000, 24],
  ];

  for (const [length, refs] of shapes) {
    it(`P=${length} × $ref ${refs} 回 + []: 走査せず予算超過で fail-closed`, () => {
      const { array, counter } = countingArray(length, () => 1);
      const schema = {
        $defs: { big: { prefixItems: array } },
        allOf: Array.from({ length: refs }, () => ({ $ref: '#/$defs/big' })),
      } as JsonSchema;
      const result = validateAgainstSchema(schema, []);
      // 修正前は valid:true のまま P × R 回の空回りをした。
      expect(result.valid).toBe(false);
      expect(hasRootBudgetError(result)).toBe(true);
      // 要素は 1 度も読まない（インスタンスが [] のため反復数は min(P, 0) = 0）。
      expect(counter.reads).toBe(0);
    });
  }

  it('prefixItems の通常の検証（タプル・items・短い配列）は従来どおり', () => {
    const schema: JsonSchema = {
      prefixItems: [{ type: 'string' }, { type: 'number' }],
      items: false,
    };
    expect(validateAgainstSchema(schema, ['a', 1])).toEqual({ valid: true });
    expect(validateAgainstSchema(schema, ['a'])).toEqual({ valid: true });
    expect(validateAgainstSchema(schema, ['a', 'b']).valid).toBe(false);
    expect(validateAgainstSchema(schema, ['a', 1, 2]).valid).toBe(false);
  });
});

describe('deepEqual はインスタンス側のキー数も前払いし列挙を繰り返さない', () => {
  // [enum 候補数 E, インスタンスのキー数 K]。いずれも E × K が MAX_SCAN_UNITS を超える。
  const shapes: [number, number][] = [
    [5_000, 1_000],
    [500, 10_000],
    [50, 100_000],
  ];

  for (const [candidates, keyCount] of shapes) {
    it(`enum ${candidates} 件 × K=${keyCount}: 列挙は 1 回、候補の比較は予算分で打ち切る`, () => {
      const instance = objectWithKeys(keyCount);
      const { array, counter } = countingArray(candidates, () => ({}));
      const keysSpy = spyOn(Object, 'keys');
      let result: Result;
      let enumerations: number;
      try {
        result = validateAgainstSchema({ enum: array }, instance);
        enumerations = keysSpy.mock.calls.filter(([target]) => target === instance).length;
      } finally {
        keysSpy.mockRestore();
      }
      expect(result.valid).toBe(false);
      expect(hasRootBudgetError(result)).toBe(true);
      expect(enumerations).toBe(1);
      expect(counter.reads).toBeLessThanOrEqual(Math.ceil(MAX_SCAN_UNITS / keyCount) + 1);
      expect(counter.reads).toBeLessThan(candidates);
    });
  }

  it('const / enum のオブジェクト等価は従来どおり（キー順無関係・値違い・キー数違い）', () => {
    const schema: JsonSchema = { enum: [{ a: 1, b: { c: [1, 2] } }, 'x'] };
    expect(validateAgainstSchema(schema, { b: { c: [1, 2] }, a: 1 })).toEqual({ valid: true });
    expect(validateAgainstSchema(schema, { a: 1, b: { c: [1, 3] } }).valid).toBe(false);
    expect(validateAgainstSchema(schema, { a: 1 }).valid).toBe(false);
    expect(validateAgainstSchema({ const: { a: 1 } }, { a: 1, b: 2 }).valid).toBe(false);
  });
});

describe('uniqueItems の canonicalJson は前払いの後に JSON.stringify する', () => {
  // [文字列長 S, `{uniqueItems:true}` の個数 R]。いずれも S × R が MAX_SCAN_UNITS を超える。
  const shapes: [number, number][] = [
    [500_000, 100],
    [50_000, 2_000],
    [1_000, 20_000],
  ];

  for (const [length, branches] of shapes) {
    it(`文字列 S=${length} × allOf ${branches} 件: 全長の stringify は予算分だけ`, () => {
      const big = '"'.repeat(length);
      const schema: JsonSchema = {
        allOf: Array.from({ length: branches }, () => ({ uniqueItems: true })),
      };
      const stringifySpy = spyOn(JSON, 'stringify');
      let result: Result;
      let fullLengthCalls: number;
      try {
        result = validateAgainstSchema(schema, [big]);
        fullLengthCalls = stringifySpy.mock.calls.filter(
          ([arg]) => typeof arg === 'string' && arg.length === length,
        ).length;
      } finally {
        stringifySpy.mockRestore();
      }
      expect(result.valid).toBe(false);
      expect(hasRootBudgetError(result)).toBe(true);
      // 1 回の stringify で少なくとも S + 3 単位を前払いする。修正前は R 回（予算切れ後も）走った。
      expect(fullLengthCalls).toBeLessThanOrEqual(Math.floor(MAX_SCAN_UNITS / (length + 3)));
      expect(fullLengthCalls).toBeLessThan(branches);
    });
  }

  it('巨大キーのオブジェクト要素もキー長を前払いしてから stringify する', () => {
    const length = 100_000;
    const bigKey = 'k'.repeat(length);
    const schema: JsonSchema = {
      allOf: Array.from({ length: 200 }, () => ({ uniqueItems: true })),
    };
    const stringifySpy = spyOn(JSON, 'stringify');
    let result: Result;
    let keyCalls: number;
    try {
      result = validateAgainstSchema(schema, [{ [bigKey]: 1 }]);
      keyCalls = stringifySpy.mock.calls.filter(
        ([arg]) => typeof arg === 'string' && arg.length === length,
      ).length;
    } finally {
      stringifySpy.mockRestore();
    }
    expect(result.valid).toBe(false);
    expect(keyCalls).toBeLessThanOrEqual(Math.floor(MAX_SCAN_UNITS / (length + 3)));
  });

  it('重複の検出は従来どおり（エスケープ・キー順・型の違い）', () => {
    const unique: JsonSchema = { uniqueItems: true };
    expect(validateAgainstSchema(unique, ['"', '\\', 'a"b', 1, '1', null, true])).toEqual({
      valid: true,
    });
    expect(validateAgainstSchema(unique, ['a"b', 'a"b']).valid).toBe(false);
    expect(
      validateAgainstSchema(unique, [
        { a: 1, b: 2 },
        { b: 2, a: 1 },
      ]).valid,
    ).toBe(false);
    expect(validateAgainstSchema(unique, [{ a: 1 }, { a: '1' }])).toEqual({ valid: true });
  });
});

describe('type の不一致メッセージはスキーマ側の文字列を全量保持しない', () => {
  const messageBound = 8 * (64 + 4) + 64;

  // [型名の個数 N, 型名の長さ L, $ref 参照数 R]
  const shapes: [number, number, number][] = [
    [4, 240_000, 1_100],
    [5, 100_000, 3_000],
    [200, 5_000, 1_100],
  ];

  for (const [names, nameLength, refs] of shapes) {
    it(`type 配列 ${names} 件 × ${nameLength} 文字 × $ref ${refs} 回: 違反メッセージは上限以下`, () => {
      const type = Array.from({ length: names }, (_, i) =>
        String.fromCharCode(97 + (i % 26)).repeat(nameLength),
      );
      const schema = {
        $defs: { t: { type } },
        allOf: Array.from({ length: refs }, () => ({ $ref: '#/$defs/t' })),
      } as JsonSchema;
      const result = validateAgainstSchema(schema, 1);
      const errors = result.errors ?? [];
      expect(result.valid).toBe(false);
      expect(errors.length).toBeLessThanOrEqual(MAX_ERRORS + 1);
      const longest = Math.max(...errors.map((e) => e.message.length));
      expect(longest).toBeLessThanOrEqual(messageBound);
    });
  }

  it('type が単一の巨大文字列でもメッセージは切り詰める', () => {
    const result = validateAgainstSchema({ type: 'x'.repeat(1_000_000) }, 1);
    expect(result.errors?.[0]?.message.length).toBeLessThanOrEqual(100);
  });

  it('通常の型名は従来どおりメッセージへ載る（超過分は件数で示す）', () => {
    expect(validateAgainstSchema({ type: ['string', 'null'] }, 1).errors?.[0]?.message).toBe(
      '型が string | null のいずれでもありません',
    );
    const many = Array.from({ length: 10 }, (_, i) => `t${i}`);
    const message = validateAgainstSchema({ type: many }, 1).errors?.[0]?.message ?? '';
    expect(message).toContain('t7');
    expect(message).not.toContain('t8');
    expect(message).toContain('他 2 件');
  });
});
