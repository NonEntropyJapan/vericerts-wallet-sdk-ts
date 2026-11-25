/**
 * JSON Schema（Draft 2020-12 サブセット）バリデータのユニットテスト。
 *
 * 検証内容:
 * - `type` / `enum` / `const` の適合・不適合（`integer` と `number` の包含関係を含む）。
 * - オブジェクト: `required` / `properties` / `additionalProperties` / `min|maxProperties`。
 * - 配列: `items` / `prefixItems` / `min|maxItems` / `uniqueItems`。
 * - 文字列: `minLength` / `maxLength` / `pattern` / `format`。
 * - 数値: `minimum` / `maximum` / `exclusive*` / `multipleOf`。
 * - 論理結合: `allOf` / `anyOf` / `oneOf` / `not`。
 * - `$ref` はローカル参照のみ解決し、リモート `$ref` は違反として報告する（黙って通過させない）。
 * - 必須属性違反（`required: true`）と任意属性違反（`required: false`）を区別する（FO-4）。
 * - 違反メッセージにインスタンスの値を含めない。
 */

import { describe, expect, it } from 'bun:test';
import type { JsonSchema } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

/** 違反の path 一覧を取り出す。 */
function paths(schema: JsonSchema, instance: unknown): string[] {
  return (validateAgainstSchema(schema, instance).errors ?? []).map((e) => e.path);
}

describe('validateAgainstSchema — type / enum / const', () => {
  it('type が一致すれば適合する', () => {
    expect(validateAgainstSchema({ type: 'string' }, 'x').valid).toBe(true);
  });

  it('type が不一致なら違反する', () => {
    const result = validateAgainstSchema({ type: 'string' }, 42);
    expect(result.valid).toBe(false);
    expect(result.errors?.[0]?.path).toBe('');
  });

  it('integer は number に含まれるが、number は integer に含まれない', () => {
    expect(validateAgainstSchema({ type: 'number' }, 3).valid).toBe(true);
    expect(validateAgainstSchema({ type: 'integer' }, 3).valid).toBe(true);
    expect(validateAgainstSchema({ type: 'integer' }, 3.5).valid).toBe(false);
  });

  it('type の配列指定はいずれか 1 つに適合すればよい', () => {
    expect(validateAgainstSchema({ type: ['string', 'null'] }, null).valid).toBe(true);
    expect(validateAgainstSchema({ type: ['string', 'null'] }, 1).valid).toBe(false);
  });

  it('null は type: null にのみ適合する', () => {
    expect(validateAgainstSchema({ type: 'null' }, null).valid).toBe(true);
    expect(validateAgainstSchema({ type: 'object' }, null).valid).toBe(false);
  });

  it('enum / const を深い等価で判定する', () => {
    expect(validateAgainstSchema({ enum: ['a', 'b'] }, 'b').valid).toBe(true);
    expect(validateAgainstSchema({ enum: ['a', 'b'] }, 'c').valid).toBe(false);
    expect(validateAgainstSchema({ const: { a: [1, 2] } }, { a: [1, 2] }).valid).toBe(true);
    expect(validateAgainstSchema({ const: { a: [1, 2] } }, { a: [2, 1] }).valid).toBe(false);
  });

  it('boolean スキーマ true / false を解釈する', () => {
    expect(validateAgainstSchema({ properties: { a: true } }, { a: 1 }).valid).toBe(true);
    expect(validateAgainstSchema({ properties: { a: false } }, { a: 1 }).valid).toBe(false);
  });
});

describe('validateAgainstSchema — オブジェクト', () => {
  const schema: JsonSchema = {
    type: 'object',
    required: ['name'],
    properties: { name: { type: 'string' }, age: { type: 'integer', minimum: 0 } },
  };

  it('必須プロパティが揃っていれば適合する', () => {
    expect(validateAgainstSchema(schema, { name: 'a', age: 1 }).valid).toBe(true);
  });

  it('必須プロパティ欠落は required: true の違反になる（FO-4 の対象外）', () => {
    const result = validateAgainstSchema(schema, { age: 1 });
    expect(result.valid).toBe(false);
    expect(result.errors?.[0]?.path).toBe('/name');
    expect(result.errors?.[0]?.required).toBe(true);
  });

  it('任意プロパティの違反は required: false になる（FO-4 の警告通過対象）', () => {
    const result = validateAgainstSchema(schema, { name: 'a', age: -1 });
    expect(result.valid).toBe(false);
    expect(result.errors?.[0]?.path).toBe('/age');
    expect(result.errors?.[0]?.required).toBe(false);
  });

  it('必須プロパティ配下の違反は required: true として伝播する', () => {
    const result = validateAgainstSchema(schema, { name: 123 });
    expect(result.errors?.[0]?.path).toBe('/name');
    expect(result.errors?.[0]?.required).toBe(true);
  });

  it('additionalProperties: false は宣言外プロパティを拒否する', () => {
    expect(paths({ ...schema, additionalProperties: false }, { name: 'a', extra: 1 })).toEqual([
      '/extra',
    ]);
  });

  it('additionalProperties がスキーマなら宣言外プロパティに適用される', () => {
    const withAdditional: JsonSchema = { ...schema, additionalProperties: { type: 'string' } };
    expect(validateAgainstSchema(withAdditional, { name: 'a', extra: 'ok' }).valid).toBe(true);
    expect(paths(withAdditional, { name: 'a', extra: 1 })).toEqual(['/extra']);
  });

  it('minProperties / maxProperties を検証する', () => {
    expect(validateAgainstSchema({ minProperties: 2 }, { a: 1 }).valid).toBe(false);
    expect(validateAgainstSchema({ maxProperties: 1 }, { a: 1, b: 2 }).valid).toBe(false);
  });

  it('JSON Pointer のエスケープを行う（`/` と `~`）', () => {
    const escaped: JsonSchema = { required: ['a/b', 'c~d'] };
    expect(paths(escaped, {})).toEqual(['/a~1b', '/c~0d']);
  });
});

describe('validateAgainstSchema — 配列', () => {
  it('items を全要素に適用する', () => {
    expect(paths({ type: 'array', items: { type: 'string' } }, ['a', 1, 'c'])).toEqual(['/1']);
  });

  it('prefixItems を位置ごとに適用し、超過分は items で検証する', () => {
    const schema: JsonSchema = {
      type: 'array',
      prefixItems: [{ type: 'string' }, { type: 'integer' }],
      items: { type: 'boolean' },
    };
    expect(validateAgainstSchema(schema, ['a', 1, true]).valid).toBe(true);
    expect(paths(schema, ['a', 'x', true])).toEqual(['/1']);
    expect(paths(schema, ['a', 1, 'nope'])).toEqual(['/2']);
  });

  it('items: false は prefixItems を超える要素を拒否する', () => {
    const schema: JsonSchema = { prefixItems: [{ type: 'string' }], items: false };
    expect(validateAgainstSchema(schema, ['a']).valid).toBe(true);
    expect(validateAgainstSchema(schema, ['a', 'b']).valid).toBe(false);
  });

  it('minItems / maxItems / uniqueItems を検証する', () => {
    expect(validateAgainstSchema({ minItems: 2 }, [1]).valid).toBe(false);
    expect(validateAgainstSchema({ maxItems: 1 }, [1, 2]).valid).toBe(false);
    expect(validateAgainstSchema({ uniqueItems: true }, [1, 2]).valid).toBe(true);
    expect(validateAgainstSchema({ uniqueItems: true }, [{ a: 1 }, { a: 1 }]).valid).toBe(false);
  });
});

describe('validateAgainstSchema — 文字列 / 数値', () => {
  it('minLength / maxLength を Unicode コードポイント単位で数える', () => {
    // "𝔘" はサロゲートペア（UTF-16 では 2 単位）だが 1 文字として数える。
    expect(validateAgainstSchema({ maxLength: 1 }, '𝔘').valid).toBe(true);
    expect(validateAgainstSchema({ minLength: 2 }, '𝔘').valid).toBe(false);
  });

  it('pattern に一致しなければ違反する', () => {
    expect(validateAgainstSchema({ pattern: '^a+$' }, 'aaa').valid).toBe(true);
    expect(validateAgainstSchema({ pattern: '^a+$' }, 'bbb').valid).toBe(false);
  });

  it('不正な pattern は黙って通過させず違反として報告する', () => {
    expect(validateAgainstSchema({ pattern: '(' }, 'x').valid).toBe(false);
  });

  it('既知の format を検証し、未知の format は無視する', () => {
    expect(validateAgainstSchema({ format: 'date' }, '2026-08-27').valid).toBe(true);
    expect(validateAgainstSchema({ format: 'date' }, '27/08/2026').valid).toBe(false);
    expect(validateAgainstSchema({ format: 'date-time' }, '2026-08-27T00:00:00Z').valid).toBe(true);
    expect(validateAgainstSchema({ format: 'unknown-format' }, 'anything').valid).toBe(true);
  });

  it('数値の範囲・倍数を検証する', () => {
    expect(validateAgainstSchema({ minimum: 0 }, -1).valid).toBe(false);
    expect(validateAgainstSchema({ maximum: 10 }, 11).valid).toBe(false);
    expect(validateAgainstSchema({ exclusiveMinimum: 0 }, 0).valid).toBe(false);
    expect(validateAgainstSchema({ exclusiveMaximum: 10 }, 10).valid).toBe(false);
    expect(validateAgainstSchema({ multipleOf: 0.1 }, 0.3).valid).toBe(true);
    expect(validateAgainstSchema({ multipleOf: 2 }, 3).valid).toBe(false);
  });
});

describe('validateAgainstSchema — 論理結合 / $ref', () => {
  it('allOf は全条件を要求する', () => {
    const schema: JsonSchema = { allOf: [{ type: 'string' }, { minLength: 2 }] };
    expect(validateAgainstSchema(schema, 'ab').valid).toBe(true);
    expect(validateAgainstSchema(schema, 'a').valid).toBe(false);
  });

  it('anyOf はいずれか 1 つで足りる', () => {
    const schema: JsonSchema = { anyOf: [{ type: 'string' }, { type: 'integer' }] };
    expect(validateAgainstSchema(schema, 1).valid).toBe(true);
    expect(validateAgainstSchema(schema, true).valid).toBe(false);
  });

  it('oneOf は厳密に 1 つだけ適合することを要求する', () => {
    const schema: JsonSchema = { oneOf: [{ type: 'number' }, { type: 'integer' }] };
    // 3 は number にも integer にも適合するため 2 件マッチ → 違反。
    expect(validateAgainstSchema(schema, 3).valid).toBe(false);
    expect(validateAgainstSchema(schema, 3.5).valid).toBe(true);
  });

  it('not は適合してはならない条件を表す', () => {
    expect(validateAgainstSchema({ not: { type: 'string' } }, 1).valid).toBe(true);
    expect(validateAgainstSchema({ not: { type: 'string' } }, 'x').valid).toBe(false);
  });

  it('ローカル $ref を解決する', () => {
    const schema: JsonSchema = {
      $defs: { name: { type: 'string', minLength: 1 } },
      type: 'object',
      properties: { name: { $ref: '#/$defs/name' } },
      required: ['name'],
    };
    expect(validateAgainstSchema(schema, { name: 'a' }).valid).toBe(true);
    expect(paths(schema, { name: '' })).toEqual(['/name']);
  });

  it('リモート $ref は解決せず違反として報告する（黙って通過させない）', () => {
    const schema: JsonSchema = { $ref: 'https://example.com/schema.json' };
    expect(validateAgainstSchema(schema, {}).valid).toBe(false);
  });

  it('解決できないローカル $ref も違反として報告する', () => {
    expect(validateAgainstSchema({ $ref: '#/$defs/missing' }, {}).valid).toBe(false);
  });

  it('循環 $ref は深さ上限で打ち切り、スタックを枯渇させない', () => {
    const schema: JsonSchema = { $defs: { loop: { $ref: '#/$defs/loop' } }, $ref: '#/$defs/loop' };
    expect(validateAgainstSchema(schema, {}).valid).toBe(false);
  });
});

describe('validateAgainstSchema — セキュリティ', () => {
  it('違反メッセージにインスタンスの値を含めない', () => {
    const secret = 'my-social-security-number-123456';
    const schema: JsonSchema = {
      type: 'object',
      required: ['ssn'],
      properties: { ssn: { type: 'integer' } },
    };
    const result = validateAgainstSchema(schema, { ssn: secret });
    expect(result.valid).toBe(false);
    for (const error of result.errors ?? []) {
      expect(error.message).not.toContain(secret);
    }
  });

  it('未知のキーワードは制約なしとして無視する', () => {
    expect(validateAgainstSchema({ 'x-vendor-rule': 'anything' }, { a: 1 }).valid).toBe(true);
  });
});
