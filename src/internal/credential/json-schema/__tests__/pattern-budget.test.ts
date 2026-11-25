/**
 * 評価不能な `pattern` の fail-closed、`patternProperties` のコンパイル再利用、
 * `uniqueItems` / `enum` / `const` の走査量予算の回帰テスト。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../__tests__/heavy-input-timeout.js';
import type { SafeRegex, SafeRegexError } from '../../../primitives/safe-regex/index.js';
import { type Context, MAX_EVALUATIONS, MAX_REGEX_STEPS, MAX_SCAN_UNITS } from '../internals.js';
import { planObjectProperties } from '../object-properties.js';
import type { JsonSchema } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

function hasRootViolation(schema: JsonSchema, instance: unknown): boolean {
  const result = validateAgainstSchema(schema, instance);
  return (
    result.valid === false && (result.errors?.some((e) => e.path === '' && e.required) ?? false)
  );
}

// `if` / `then` / `else` は検証器が解釈しないため対象外。
describe('評価不能な pattern は分岐の内側でも fail-open にならない', () => {
  it.each([
    ['先読み', '^(?=.*admin)'],
    ['後読み', '(?<=a)x'],
    ['後方参照', '(a)\\1'],
    ['構文不正', '(unclosed'],
  ])('not の内側の %s pattern は適合扱いにならない', (_label, pattern) => {
    expect(hasRootViolation({ not: { type: 'string', pattern } }, 'admin-x')).toBe(true);
  });

  it('評価できる pattern の not は従来どおり判定する', () => {
    const schema: JsonSchema = { not: { type: 'string', pattern: 'admin' } };
    expect(validateAgainstSchema(schema, 'admin-x').valid).toBe(false);
    expect(validateAgainstSchema(schema, 'user').valid).toBe(true);
  });

  it('oneOf / anyOf の枝に評価不能な pattern があれば必須違反にする', () => {
    expect(hasRootViolation({ anyOf: [{ pattern: '(?=a)' }, { type: 'number' }] }, 'abc')).toBe(
      true,
    );
    expect(hasRootViolation({ oneOf: [{ pattern: '(a)\\1' }, { type: 'number' }] }, 'aa')).toBe(
      true,
    );
  });

  it('not の内側の patternProperties の評価不能な pattern も必須違反にする', () => {
    const schema: JsonSchema = {
      not: { patternProperties: { '^(?=a)': { type: 'string' } }, additionalProperties: false },
    };
    expect(hasRootViolation(schema, { abc: 'x' })).toBe(true);
  });
});

describe('patternProperties は検証内で 1 回だけコンパイルする', () => {
  it('同じ patternProperties を多数のオブジェクトへ適用しても、エントリは 1 回しか引かない', () => {
    // コンパイル結果の再利用を実時間ではなく回数で pin する。再利用が無いと、オブジェクト
    // 1 個ごとに全エントリのコンパイル結果を `sources` から引き直す（entryCount × 呼び出し回数）。
    class CountingMap<K, V> extends Map<K, V> {
      lookups = 0;
      override get(key: K): V | undefined {
        this.lookups += 1;
        return super.get(key);
      }
    }
    const entryCount = 50;
    const patternProperties: Record<string, JsonSchema> = {};
    for (let i = 0; i < entryCount; i += 1) {
      patternProperties[`^key${i}-[a-z]+$`] = { type: 'string' };
    }
    const schema: JsonSchema = { patternProperties };
    const sources = new CountingMap<string, SafeRegex | SafeRegexError>();
    const ctx: Context = {
      errors: [],
      root: schema,
      budget: {
        remaining: MAX_EVALUATIONS,
        exhausted: false,
        regex: { remaining: MAX_REGEX_STEPS },
        scanRemaining: MAX_SCAN_UNITS,
      },
      compiled: { sources, patternProperties: new WeakMap() },
    };

    for (let i = 0; i < 200; i += 1) {
      const plan = planObjectProperties(ctx, schema, [`key${i % entryCount}-a`]);
      expect(plan.assignments).toHaveLength(1);
    }

    expect(sources.lookups).toBe(entryCount);
  });

  it('キャッシュしても各オブジェクトのキーを毎回正しく割り当てる', () => {
    const schema: JsonSchema = {
      type: 'array',
      items: { patternProperties: { '^n_': { type: 'number' } }, additionalProperties: false },
    };
    expect(validateAgainstSchema(schema, [{ n_a: 1 }, { n_b: 2 }]).valid).toBe(true);
    const result = validateAgainstSchema(schema, [{ n_a: 1 }, { n_b: 'x', other: 1 }]);
    expect(result.errors?.map((e) => e.path).sort()).toEqual(['/1/n_b', '/1/other']);
  });

  it('同じ pattern を多数の要素へ適用しても検証全体の結果は変わらない', () => {
    const schema: JsonSchema = { type: 'array', items: { type: 'string', pattern: '^a+$' } };
    const instance = [...Array.from({ length: 5_000 }, () => 'aaa'), 'b'];
    const result = validateAgainstSchema(schema, instance);
    expect(result.errors?.map((e) => e.path)).toEqual(['/5000']);
  });
});

describe('uniqueItems / enum / const の走査量は予算に計上される', () => {
  it('2 要素 × 約 500KB を allOf で走査量予算を超えるまで走査させると必須違反にする', () => {
    // 1 回の走査は約 100 万で、予算（MAX_SCAN_UNITS = 4,000,000）は 4 回強で尽きる。2 要素は相異なるため
    // 予算が無ければ全枝が適合して valid になる。実時間ではなく「違反になる」ことで打ち切りを pin する。
    const big = (ch: string) => ch.repeat(500_000);
    const instance = [big('a'), big('b')];
    const schema: JsonSchema = {
      allOf: Array.from({ length: 8 }, () => ({ type: 'array', uniqueItems: true })),
    };
    expect(validateAgainstSchema({ type: 'array', uniqueItems: true }, instance).valid).toBe(true);
    expect(hasRootViolation(schema, instance)).toBe(true);
  });

  it('巨大要素でも 1 回の uniqueItems は従来どおり判定できる', () => {
    const big = (ch: string) => ch.repeat(500_000);
    const unique = { uniqueItems: true };
    expect(validateAgainstSchema(unique, [big('a'), big('b')]).valid).toBe(true);
    expect(validateAgainstSchema(unique, [big('a'), big('a')]).valid).toBe(false);
  });

  it('巨大な const / enum の等価判定を allOf で多重化しても必須違反にする', () => {
    const value = Array.from({ length: 20_000 }, (_, i) => ({ i }));
    const copy = structuredClone(value);
    const constSchema: JsonSchema = {
      allOf: Array.from({ length: 200 }, () => ({ const: value })),
    };
    const enumSchema: JsonSchema = {
      allOf: Array.from({ length: 200 }, () => ({ enum: [value] })),
    };
    // 対照: 1 回の等価判定は予算内で一致する（違反は多重化による予算超過に由来する）。
    expect(validateAgainstSchema({ const: value }, copy).valid).toBe(true);
    expect(validateAgainstSchema({ enum: [value] }, copy).valid).toBe(true);
    expect(hasRootViolation(constSchema, copy)).toBe(true);
    expect(hasRootViolation(enumSchema, copy)).toBe(true);
  });

  it('通常サイズの const / enum は従来どおり判定する', () => {
    expect(validateAgainstSchema({ const: { a: [1, { b: 2 }] } }, { a: [1, { b: 2 }] }).valid).toBe(
      true,
    );
    expect(validateAgainstSchema({ const: { a: 1 } }, { a: 2 }).valid).toBe(false);
    expect(validateAgainstSchema({ enum: ['x', [1], null] }, [1]).valid).toBe(true);
    expect(validateAgainstSchema({ enum: ['x', [1], null] }, [2]).valid).toBe(false);
  });
});
