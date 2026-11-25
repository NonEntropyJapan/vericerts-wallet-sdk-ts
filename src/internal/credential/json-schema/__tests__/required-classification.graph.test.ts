/**
 * `required` の分類をスキーマグラフ全体で行うことの回帰テスト。
 *
 * `required` と `properties` が別ノード（`allOf` の別枝・`$ref` の兄弟・`$ref` 先）に分かれていても、必須属性の型・形式違反は
 * `required: true`（fail-closed）でなければならない。ノード自身の `required` だけで分類すると、これらの形で
 * `required: false` に落ち、FO-4 が `valid: true`（警告通過）を返していた。
 *
 * 任意プロパティの違反が `false` のまま（FO-4 を殺さない）ことも両側から固定する。
 */

import { describe, expect, it } from 'bun:test';
import { consumeScan, type EvaluationBudget } from '../internals.js';
import { collectRequiredKeys } from '../required-keys.js';
import type { JsonSchema } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

const AGE = { type: 'integer' } as const;

/** `path` の違反の `required` を返す（違反が無ければ undefined、複数なら全部 true のときだけ true）。 */
function requiredAt(schema: JsonSchema, instance: unknown, path: string): boolean | undefined {
  const matched = (validateAgainstSchema(schema, instance).errors ?? []).filter(
    (error) => error.path === path,
  );
  return matched.length === 0 ? undefined : matched.every((error) => error.required);
}

function budget(scanRemaining: number): EvaluationBudget {
  return { remaining: 1000, exhausted: false, regex: { remaining: 1000 }, scanRemaining };
}

describe('required は allOf / $ref に分割しても必須として分類する', () => {
  const BASE: JsonSchema = { properties: { age: AGE } };
  const cases: readonly (readonly [string, JsonSchema])[] = [
    ['同一ノード（基準）', { required: ['age'], properties: { age: AGE } }],
    [
      'properties と別ノードの allOf 枝の required',
      { properties: { age: AGE }, allOf: [{ required: ['age'] }] },
    ],
    ['allOf の枝同士で properties / required を分割', { allOf: [BASE, { required: ['age'] }] }],
    [
      '$ref の兄弟の required',
      { $ref: '#/$defs/B', required: ['age'], $defs: { B: BASE } } as JsonSchema,
    ],
    [
      'allOf 枝の $ref 先が properties だけ',
      { required: ['age'], allOf: [{ $ref: '#/$defs/B' }], $defs: { B: BASE } } as JsonSchema,
    ],
    [
      '$ref 先の required（properties は参照元）',
      {
        $ref: '#/$defs/R',
        properties: { age: AGE },
        $defs: { R: { required: ['age'] } },
      } as JsonSchema,
    ],
    [
      '入れ子の allOf → $ref → allOf',
      {
        allOf: [{ allOf: [{ $ref: '#/$defs/R' }] }, BASE],
        $defs: { R: { allOf: [{ required: ['age'] }] } },
      } as JsonSchema,
    ],
    [
      'anyOf / oneOf の枝が列挙した required',
      { properties: { age: AGE }, anyOf: [{ required: ['age'] }, { required: ['age', 'x'] }] },
    ],
  ];

  for (const [name, schema] of cases) {
    it(`型違反は required: true（${name}）`, () => {
      expect(requiredAt(schema, { age: 'not-an-int' }, '/age')).toBe(true);
    });
    it(`欠落も required: true（${name}）`, () => {
      // anyOf の枝の required は「いずれか」なので、欠落違反はルートの anyOf 失敗として報告される（いずれも必須違反）。
      const errors = validateAgainstSchema(schema, {}).errors ?? [];
      expect(errors.length).toBeGreaterThan(0);
      expect(errors.every((error) => error.required)).toBe(true);
    });
    it(`適合するインスタンスは valid（${name}）`, () => {
      expect(validateAgainstSchema(schema, { age: 3 }).valid).toBe(true);
    });
  }

  it('同じ分割の任意プロパティは required: false のまま（FO-4 を殺さない）', () => {
    const schema: JsonSchema = {
      allOf: [{ properties: { age: AGE, nick: { type: 'string' } } }, { required: ['age'] }],
    };
    expect(requiredAt(schema, { age: 3, nick: 1 }, '/nick')).toBe(false);
    expect(requiredAt(schema, { age: 'x', nick: 1 }, '/age')).toBe(true);
  });

  it('入れ子のオブジェクトの required は親の分類へ漏れない', () => {
    const schema: JsonSchema = {
      properties: { outer: { allOf: [{ properties: { inner: AGE } }, { required: ['inner'] }] } },
    };
    // outer は必須ではない（任意）。outer 配下の違反は outer が任意なので false だが、inner は必須なので true。
    expect(requiredAt(schema, { outer: { inner: 'x' } }, '/outer/inner')).toBe(true);
    const optionalOuter: JsonSchema = {
      properties: { outer: { properties: { inner: AGE } } },
      allOf: [{ properties: { other: AGE } }],
    };
    expect(requiredAt(optionalOuter, { outer: { inner: 'x' } }, '/outer/inner')).toBe(false);
  });

  it('入れ子の分割 required が親の properties の分類へ効く（2 段）', () => {
    const schema: JsonSchema = {
      required: ['outer'],
      properties: { outer: { properties: { inner: AGE }, allOf: [{ required: ['inner'] }] } },
    };
    expect(requiredAt(schema, { outer: { inner: 'x' } }, '/outer/inner')).toBe(true);
  });
});

describe('required の集約は予算を前払いし、循環・多重参照で増えない', () => {
  it('循環 $ref を辿っても打ち切られず、訪問は 1 ノード 1 回', () => {
    const schema = {
      $ref: '#/$defs/A',
      $defs: {
        A: { allOf: [{ $ref: '#/$defs/B' }], required: ['a'] },
        B: { $ref: '#/$defs/A', required: ['b'] },
      },
    } as JsonSchema;
    const keys = collectRequiredKeys(schema, schema, budget(1000));
    expect([...(keys ?? [])].sort()).toEqual(['a', 'b']);
  });

  it('同じ部分スキーマを何度指す allOf でも走査量は参照先 1 回ぶんしか増えない', () => {
    const shared: JsonSchema = { required: ['k'] };
    const once = budget(1_000_000);
    collectRequiredKeys({}, { allOf: [shared] }, once);
    const many = budget(1_000_000);
    collectRequiredKeys({}, { allOf: Array.from({ length: 50 }, () => shared) }, many);
    const used = (b: EvaluationBudget): number => 1_000_000 - b.scanRemaining;
    // 枝の配列長（50）は前払いするが、`shared` の本体（required 配列 1 件）は 1 回しか走査しない。
    expect(used(many) - used(once)).toBe(49);
  });

  it('予算が足りなければ途中の集合を返さず undefined、exhausted で検証全体が fail-closed になる', () => {
    const tight = budget(2);
    expect(
      collectRequiredKeys({}, { allOf: [{ required: ['a', 'b', 'c'] }] }, tight),
    ).toBeUndefined();
    expect(tight.exhausted).toBe(true);
    // 予算が尽きた後は consumeScan が常に失敗する（以降の走査をしない）。
    expect(consumeScan(tight, 1)).toBe(false);
  });

  it('巨大な allOf のスキーマ（予算超過）は valid: true にならず必須違反で閉じる', () => {
    const schema: JsonSchema = {
      properties: { age: AGE },
      allOf: Array.from({ length: 1_000 }, () => ({
        allOf: new Array(4_001).fill({ required: ['age'] }),
      })),
    };
    const result = validateAgainstSchema(schema, { age: 'x' });
    expect(result.valid).toBe(false);
    expect(result.errors?.some((error) => error.path === '' && error.required)).toBe(true);
  });
});
