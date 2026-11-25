/**
 * スキーマ側配列の走査・違反件数・パターン × キーの予算。
 *
 * 実時間ではなく決定的なカウンタ（配列要素の読み出し回数・違反件数・正規表現の試行回数）で pin する。
 * 修正前は E × N / P × K / required × 評価回数に比例して増え、1 MiB 以内の入力で数十秒〜メモリ枯渇に至った。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { SafeRegexError } from '../../../primitives/safe-regex/index.js';
import {
  type Context,
  MAX_ERRORS,
  MAX_EVALUATIONS,
  MAX_REGEX_STEPS,
  MAX_SCAN_UNITS,
} from '../internals.js';
import { planObjectProperties } from '../object-properties.js';
import type { JsonSchema } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

/** 添字読み出しを数える配列（`Array.isArray` は `true`）。 */
function countingArray<T>(length: number, make: (i: number) => T) {
  const target = Array.from({ length }, (_, i) => make(i));
  const counter = { reads: 0 };
  const proxy = new Proxy(target, {
    get(t, key, receiver) {
      if (typeof key === 'string' && /^\d+$/.test(key)) {
        counter.reads += 1;
      }
      return Reflect.get(t, key, receiver);
    },
  });
  return { array: proxy, counter };
}

// 並列実行で CPU が逼迫しても決定的な検証が時間切れで落ちないようにする（判定はカウンタで行う）。
setDefaultTimeout(30_000);

const BUDGET_ERROR_PATH = '';

function hasRootBudgetError(result: ReturnType<typeof validateAgainstSchema>): boolean {
  return (result.errors ?? []).some(
    (e) => e.path === BUDGET_ERROR_PATH && e.required && e.message.includes('評価量'),
  );
}

describe('required の線形探索は二次時間にならない', () => {
  it('required × 割り当て数のあいだで `Array.prototype.includes` を呼ばず、結果も正しい', () => {
    const n = 5_000;
    const required: string[] = [];
    const instance: Record<string, number> = {};
    for (let i = 0; i < n; i += 1) {
      required.push(`k${i}`);
      instance[`k${i}`] = 1;
    }
    const schema: JsonSchema = { required, additionalProperties: { type: 'number' } };

    const original = Array.prototype.includes;
    let largeScans = 0;
    Array.prototype.includes = function (this: unknown[], ...args: [unknown, number?]) {
      if (this.length >= 1_000) {
        largeScans += 1;
      }
      return original.apply(this, args);
    };
    try {
      expect(validateAgainstSchema(schema, instance).valid).toBe(true);
      expect(validateAgainstSchema(schema, { ...instance, k0: 'x' }).errors?.[0]?.required).toBe(
        true,
      );
    } finally {
      Array.prototype.includes = original;
    }
    expect(largeScans).toBe(0);
  });
});

describe('patternProperties は予算切れ後にパターン × キーを回し続けない', () => {
  it('正規表現が too-complex を返した時点で以降のキー・パターンの試行を止める', () => {
    const patterns = 1_000;
    const keyCount = 1_000;
    const calls = { n: 0 };
    const limit = 10;
    const fake = {
      test() {
        calls.n += 1;
        if (calls.n > limit) {
          throw new SafeRegexError('too-complex');
        }
        return false;
      },
    };
    const raw: Record<string, unknown> = {};
    for (let i = 0; i < patterns; i += 1) {
      raw[`^p${i}$`] = {};
    }
    const schema = { patternProperties: raw } as JsonSchema;
    const ctx: Context = {
      errors: [],
      root: schema,
      budget: {
        remaining: MAX_EVALUATIONS,
        exhausted: false,
        regex: { remaining: MAX_REGEX_STEPS },
        scanRemaining: MAX_SCAN_UNITS,
      },
      compiled: { sources: new Map(), patternProperties: new WeakMap() },
    };
    ctx.compiled.patternProperties.set(raw, {
      matchers: Object.values(raw).map((sub) => ({ regex: fake, schema: sub })),
      unusable: false,
    });

    const keys = Array.from({ length: keyCount }, (_, i) => `k${i}`);
    const plan = planObjectProperties(ctx, schema, keys);

    expect(plan.patternUnusable).toBe(true);
    expect(ctx.budget.exhausted).toBe(true);
    // 予算切れの 1 回で止まる（修正前は 1,000 × 1,000 = 100 万回）。
    expect(calls.n).toBe(limit + 1);
  });

  it('予算を使い切るスキーマは違反として報告し、適合扱いにしない', () => {
    const raw: Record<string, unknown> = {};
    for (let i = 0; i < 600; i += 1) {
      raw[`^p${i}$`] = {};
    }
    // 長いキーで正規表現の走査ステップを稼ぐ（パターン 600 × キー 100 × 200 文字 = 1,200 万 > 500 万）。
    const instance: Record<string, number> = {};
    for (let i = 0; i < 100; i += 1) {
      instance[`k${i}`.padEnd(200, 'x')] = 1;
    }
    const result = validateAgainstSchema({ patternProperties: raw } as JsonSchema, instance);
    expect(result.valid).toBe(false);
    expect(hasRootBudgetError(result)).toBe(true);
  });
});

describe('違反件数に上限がある', () => {
  it('required 5,000 件 × allOf/$ref 100 回でも違反は MAX_ERRORS + ルート 1 件に収まり、fail-closed', () => {
    const required = Array.from({ length: 5_000 }, (_, i) => `r${i}`);
    const schema = {
      $defs: { r: { required } },
      allOf: Array.from({ length: 100 }, () => ({ $ref: '#/$defs/r' })),
    } as JsonSchema;
    const result = validateAgainstSchema(schema, {});
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(MAX_ERRORS + 1);
    expect(hasRootBudgetError(result)).toBe(true);
  });

  it('items 経由の多重評価でも上限を超えない', () => {
    const required = Array.from({ length: 5_000 }, (_, i) => `r${i}`);
    const schema = { type: 'array', items: { required } } as JsonSchema;
    const result = validateAgainstSchema(
      schema,
      Array.from({ length: 20 }, () => ({})),
    );
    expect(result.errors?.length).toBeLessThanOrEqual(MAX_ERRORS + 1);
    expect(hasRootBudgetError(result)).toBe(true);
  });

  it('anyOf の不適合な分岐が大量の違反を持っても、適合する分岐があれば適合する', () => {
    const required = Array.from({ length: 1_500 }, (_, i) => `r${i}`);
    expect(validateAgainstSchema({ anyOf: [{ required }, {}] }, {}).valid).toBe(true);
  });

  it('上限以内の違反は全件そのまま返す', () => {
    const result = validateAgainstSchema({ required: ['a', 'b', 'c'] }, {});
    expect(result.errors?.map((e) => e.path)).toEqual(['/a', '/b', '/c']);
  });
});

describe('スキーマ側配列の走査は走査量予算に計上される', () => {
  const instance = Array.from({ length: 1_000 }, () => 0);
  const E = 10_000;

  it('type 配列: 読み出し総数が走査量予算で頭打ちになり、fail-closed', () => {
    const { array, counter } = countingArray(E, () => 'string');
    const result = validateAgainstSchema(
      { type: 'array', items: { type: array } } as JsonSchema,
      instance,
    );
    // 1 ノードで `filter` と `some` が各 1 周する。修正前は 2 × E × 2,000 = 8,000 万。
    expect(counter.reads).toBeLessThanOrEqual(2 * MAX_SCAN_UNITS);
    expect(hasRootBudgetError(result)).toBe(true);
  });

  it('enum: 予算を使い切ったら残りの候補を比較しない', () => {
    const { array, counter } = countingArray(E, (i) => -1 - i);
    const result = validateAgainstSchema(
      { type: 'array', items: { enum: array } } as JsonSchema,
      instance,
    );
    expect(counter.reads).toBeLessThanOrEqual(MAX_SCAN_UNITS + E);
    expect(hasRootBudgetError(result)).toBe(true);
  });

  it('allOf に並べた true も予算で打ち切る（boolean スキーマの早期 return も 1 単位消費）', () => {
    const { array, counter } = countingArray(E, () => true);
    const result = validateAgainstSchema(
      {
        type: 'array',
        items: { $ref: '#/$defs/a' },
        $defs: { a: { allOf: array } },
      } as JsonSchema,
      instance,
    );
    expect(counter.reads).toBeLessThanOrEqual(MAX_SCAN_UNITS + E);
    expect(hasRootBudgetError(result)).toBe(true);
  });

  it('対照: 現実的な大きさの enum（250 件）× 1,000 要素は従来どおり適合する', () => {
    const countries = Array.from({ length: 250 }, (_, i) => `C${i}`);
    const result = validateAgainstSchema(
      { type: 'array', items: { enum: countries } },
      Array.from({ length: 1_000 }, () => 'C249'),
    );
    expect(result.valid).toBe(true);
  });
});
