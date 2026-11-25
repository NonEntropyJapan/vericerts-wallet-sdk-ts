/**
 * boolean スキーマ（`true` / `false`）を全てのサブスキーマ位置で Draft 2020-12 どおりに評価する回帰テスト。
 *
 * 期待値は `ajv`（Draft 2020-12）と同一スキーマ × インスタンスで突き合わせた結果。修正前は
 * `not: true` が無視されて常に適合（fail-open）になり、`$ref` の解決先が boolean だと解決不能として全拒否されていた。
 */

import { describe, expect, it } from 'bun:test';
import { resolveRef } from '../../ref.js';
import type { JsonSchema } from '../../types.js';
import { validateAgainstSchema } from '../../validate.js';

type Case = readonly [name: string, schema: JsonSchema, instance: unknown, valid: boolean];

const CASES: readonly Case[] = [
  // not
  ['not: true は常に不適合', { not: true }, 'x', false],
  ['not: false は常に適合', { not: false }, 'x', true],
  ['not: { not: true } は適合', { not: { not: true } }, 1, true],
  ['not: { not: false } は不適合', { not: { not: false } }, 1, false],
  ['ssn を禁止する not: true', { properties: { ssn: { not: true } } }, { ssn: '1' }, false],
  ['ssn を禁止する not: true（欠落は適合）', { properties: { ssn: { not: true } } }, {}, true],
  ['items の not: true', { items: { not: true } }, [1], false],
  ['items の not: true（空配列は適合）', { items: { not: true } }, [], true],
  ['not: { $ref -> true } は不適合', { not: { $ref: '#/$defs/t' }, $defs: { t: true } }, 1, false],
  ['not: { $ref -> false } は適合', { not: { $ref: '#/$defs/f' }, $defs: { f: false } }, 1, true],
  // $ref の解決先
  ['$ref -> true は適合', { $ref: '#/$defs/any', $defs: { any: true } }, 'x', true],
  ['$ref -> false は不適合', { $ref: '#/$defs/no', $defs: { no: false } }, 'x', false],
  ['$ref -> properties/a(true)', { $ref: '#/properties/a', properties: { a: true } }, 1, true],
  ['$ref -> properties/a(false)', { $ref: '#/properties/a', properties: { a: false } }, 1, false],
  [
    '$ref -> true と兄弟キーワード（兄弟は評価される）',
    { $ref: '#/$defs/any', type: 'string', $defs: { any: true } },
    1,
    false,
  ],
  [
    'プロパティの $ref -> true',
    { properties: { a: { $ref: '#/$defs/any' } }, $defs: { any: true } },
    { a: 1 },
    true,
  ],
  [
    'プロパティの $ref -> false',
    { properties: { a: { $ref: '#/$defs/no' } }, $defs: { no: false } },
    { a: 1 },
    false,
  ],
  // allOf / anyOf / oneOf
  ['allOf [true, false]', { allOf: [true, false] }, 1, false],
  ['allOf [true, true]', { allOf: [true, true] }, 1, true],
  ['anyOf [false, true]', { anyOf: [false, true] }, 1, true],
  ['anyOf [false, false]', { anyOf: [false, false] }, 1, false],
  ['oneOf [true, false]', { oneOf: [true, false] }, 1, true],
  ['oneOf [true, true]', { oneOf: [true, true] }, 1, false],
  ['oneOf [false, false]', { oneOf: [false, false] }, 1, false],
  // properties / additionalProperties / patternProperties
  ['properties の false（存在すれば不適合）', { properties: { a: false } }, { a: 1 }, false],
  ['properties の false（欠落は適合）', { properties: { a: false } }, {}, true],
  ['properties の true', { properties: { a: true } }, { a: 1 }, true],
  ['additionalProperties: false', { additionalProperties: false }, { a: 1 }, false],
  ['additionalProperties: true', { additionalProperties: true }, { a: 1 }, true],
  ['patternProperties の false', { patternProperties: { '^a': false } }, { ab: 1 }, false],
  ['patternProperties の true', { patternProperties: { '^a': true } }, { ab: 1 }, true],
  [
    'patternProperties の not: true',
    { patternProperties: { '^a': { not: true } } },
    { ab: 1 },
    false,
  ],
  // items / prefixItems
  ['items: false（空配列は適合）', { items: false }, [], true],
  ['items: false（要素があれば不適合）', { items: false }, [1], false],
  ['items: true', { items: true }, [1], true],
  ['prefixItems [true, false]（2 番目が不適合）', { prefixItems: [true, false] }, [1, 2], false],
  ['prefixItems [true, false]（1 要素は適合）', { prefixItems: [true, false] }, [1], true],
  ['prefixItems + items: false', { prefixItems: [true], items: false }, [1, 2], false],
  ['prefixItems [not: true]', { prefixItems: [{ not: true }] }, [1], false],
];

describe('boolean スキーマを全サブスキーマ位置で ajv と同じに評価する', () => {
  it.each(CASES)('%s', (_name, schema, instance, valid) => {
    expect(validateAgainstSchema(schema, instance).valid).toBe(valid);
  });
});

describe('boolean スキーマ違反の必須分類', () => {
  it('not: true の違反は必須違反（required: true）', () => {
    const result = validateAgainstSchema({ properties: { ssn: { not: true } } }, { ssn: '1' });
    expect(result.errors).toEqual([
      { path: '/ssn', message: 'not で禁止された条件に適合します', required: true },
    ]);
  });

  it('任意プロパティの $ref -> false は任意違反（required: false）', () => {
    const schema = { properties: { a: { $ref: '#/$defs/no' } }, $defs: { no: false } };
    expect(validateAgainstSchema(schema, { a: 1 }).errors?.map((e) => e.required)).toEqual([false]);
  });

  it('required 列挙プロパティの $ref -> false は必須違反（required: true）', () => {
    const schema = {
      required: ['a'],
      properties: { a: { $ref: '#/$defs/no' } },
      $defs: { no: false },
    };
    expect(validateAgainstSchema(schema, { a: 1 }).errors?.map((e) => e.required)).toEqual([true]);
  });

  it('$ref -> boolean を含むグラフでも別ノードの required でプロパティを必須に分類する', () => {
    const schema = {
      allOf: [
        { $ref: '#/$defs/any' },
        { properties: { a: { type: 'string' } } },
        { required: ['a'] },
      ],
      $defs: { any: true },
    };
    expect(validateAgainstSchema(schema, { a: 1 }).errors?.map((e) => e.required)).toEqual([true]);
  });
});

describe('resolveRef — boolean スキーマを返す', () => {
  it.each([true, false])('解決先が %s のとき boolean を返す', (flag) => {
    expect(resolveRef({ $defs: { x: flag } }, '#/$defs/x')).toBe(flag);
  });

  it('boolean 以外の非スキーマ値（数値・文字列・null）は解決不能のまま', () => {
    const root = { $defs: { n: 1, s: 'x', z: null } };
    expect(resolveRef(root, '#/$defs/n')).toBeUndefined();
    expect(resolveRef(root, '#/$defs/s')).toBeUndefined();
    expect(resolveRef(root, '#/$defs/z')).toBeUndefined();
  });
});
