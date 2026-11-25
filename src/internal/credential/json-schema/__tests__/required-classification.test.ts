/**
 * 違反の必須 / 任意分類の回帰テスト（critical 3 / critical 4 / major 2）。
 *
 * `SchemaError.required` は FO-4（`credentialSchema` の**任意属性**
 * バリデーション違反 = 警告通過）を成立させるための分類であり、必須制約まで `false` にすると
 * FO-4 が「何でも通す穴」になる。逆に一律 `true` にすると FO-4 自体が機能しなくなる。
 * 本ファイルはその境界を両側から固定する。
 *
 * 検証内容:
 * - critical 3: ルート（`path` が空文字列）の構造違反は必須違反（`required: true`）。
 *   修正前は `credentialSubject` の型が丸ごと食い違っても `required: false` だった。
 * - critical 4: `anyOf` / `oneOf` / `not` の失敗は必須違反。修正前は親の `required` フラグで
 *   記録していたため、ルート直下では常に `false` になり、必須構造を `oneOf` で表現した
 *   スキーマが素通りした。
 * - FO-4 の維持: `required` に列挙されていない任意プロパティ配下の型・形式違反は `false` のまま。
 * - major 2: `patternProperties` に一致するキーを `additionalProperties` の対象にしない
 *   （適合するクレデンシャルへ偽の違反を報告しない）。
 */

import { describe, expect, it } from 'bun:test';
import type { JsonSchema } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

/** `name` が必須、`nickname` が任意のスキーマ。 */
const PERSON: JsonSchema = {
  type: 'object',
  required: ['name'],
  properties: {
    name: { type: 'string', minLength: 1 },
    nickname: { type: 'string', maxLength: 8 },
  },
};

describe('ルートの構造違反は必須違反として分類する（critical 3）', () => {
  it('credentialSubject の型がスキーマと矛盾すれば required: true になる', () => {
    const result = validateAgainstSchema(PERSON, ['totally', 'wrong', 'shape']);

    expect(result.valid).toBe(false);
    // 修正前はここが false になり、FO-4 で valid: true として警告通過していた。
    expect(result.errors).toEqual([
      { path: '', message: '型が object ではありません', required: true },
    ]);
  });

  it('ルートの enum / const / minProperties 違反も必須違反になる', () => {
    for (const schema of [
      { enum: ['a', 'b'] },
      { const: 'a' },
      { minProperties: 2 },
    ] satisfies JsonSchema[]) {
      const errors = validateAgainstSchema(schema, { z: 1 }).errors ?? [];
      expect(errors.length).toBeGreaterThan(0);
      expect(errors.every((error) => error.path === '' && error.required)).toBe(true);
    }
  });

  it('ルートの $ref 解決失敗も必須違反になる（黙って通過させない）', () => {
    const errors = validateAgainstSchema({ $ref: 'https://example.com/s.json' }, {}).errors ?? [];
    expect(errors.some((error) => error.path === '' && error.required)).toBe(true);
  });
});

describe('論理結合キーワードの失敗は必須違反として分類する（critical 4）', () => {
  it('oneOf で必須構造を表現したスキーマを警告通過させない', () => {
    // Issuer がこのイディオムを選ぶだけで必須クレームを省略できてはならない。
    const schema: JsonSchema = { oneOf: [{ required: ['a'] }, { required: ['b'] }] };
    const result = validateAgainstSchema(schema, { c: 1 });

    expect(result.valid).toBe(false);
    expect(result.errors?.every((error) => error.required)).toBe(true);
  });

  it('任意プロパティ配下の anyOf / oneOf / not の失敗も必須違反になる', () => {
    const cases: JsonSchema[] = [
      { properties: { opt: { anyOf: [{ type: 'string' }, { type: 'integer' }] } } },
      { properties: { opt: { oneOf: [{ required: ['a'] }, { required: ['b'] }] } } },
      { properties: { opt: { not: { type: 'boolean' } } } },
    ];
    for (const schema of cases) {
      const errors = validateAgainstSchema(schema, { opt: true }).errors ?? [];
      expect(errors.some((error) => error.path === '/opt' && error.required)).toBe(true);
    }
  });

  it('allOf は透過的な連言なので分類を変えない（FO-4 を殺さない）', () => {
    // `allOf` を外して型制約を直接書いた場合と同じ分類でなければならない。
    const schema: JsonSchema = { properties: { opt: { allOf: [{ type: 'string' }] } } };
    const result = validateAgainstSchema(schema, { opt: 1 });

    expect(result.valid).toBe(false);
    expect(result.errors).toEqual([
      { path: '/opt', message: '型が string ではありません', required: false },
    ]);
  });
});

describe('任意プロパティ配下の違反は任意違反のまま（FO-4 の維持）', () => {
  it('required に列挙されていないプロパティの型・形式違反は required: false', () => {
    const result = validateAgainstSchema(PERSON, {
      name: '山田太郎',
      nickname: 'ながすぎる愛称です',
    });

    expect(result.valid).toBe(false);
    expect(result.errors).toEqual([
      { path: '/nickname', message: '文字数が最大長 8 を超えます', required: false },
    ]);
  });

  it('必須プロパティ配下の違反とは分類が分かれる', () => {
    const errors =
      validateAgainstSchema(PERSON, { name: '', nickname: 'ながすぎる愛称です' }).errors ?? [];
    const byPath = new Map(errors.map((error) => [error.path, error.required]));

    expect(byPath.get('/name')).toBe(true);
    expect(byPath.get('/nickname')).toBe(false);
  });
});

describe('patternProperties を additionalProperties から除外する（major 2）', () => {
  const schema: JsonSchema = {
    type: 'object',
    properties: { name: { type: 'string' } },
    patternProperties: { '^ext_': { type: 'string' } },
    additionalProperties: false,
  };

  it('patternProperties に一致するキーを追加プロパティとして報告しない', () => {
    // 修正前は `ext_note` が「追加プロパティは許可されていません」として偽陽性になった。
    expect(validateAgainstSchema(schema, { name: 'a', ext_note: 'ok' }).valid).toBe(true);
  });

  it('patternProperties に一致するキーは部分スキーマで検証する（無視しない）', () => {
    const errors = validateAgainstSchema(schema, { name: 'a', ext_note: 1 }).errors ?? [];
    expect(errors.map((error) => error.path)).toEqual(['/ext_note']);
  });

  it('どのパターンにも一致しないキーは従来どおり追加プロパティとして拒否する', () => {
    const errors = validateAgainstSchema(schema, { name: 'a', other: 1 }).errors ?? [];
    expect(errors.map((error) => error.path)).toEqual(['/other']);
  });

  it('properties と patternProperties の双方に当たるキーは両方で検証する', () => {
    const both: JsonSchema = {
      properties: { ext_a: { type: 'string' } },
      patternProperties: { '^ext_': { minLength: 3 } },
    };
    expect(validateAgainstSchema(both, { ext_a: 'abc' }).valid).toBe(true);
    expect(validateAgainstSchema(both, { ext_a: 'ab' }).valid).toBe(false);
  });

  it('線形時間で評価できない patternProperties は黙って通過させず違反として報告する', () => {
    const unsafe: JsonSchema = {
      patternProperties: { '^(?=a)': { type: 'string' } },
      additionalProperties: false,
    };
    const errors = validateAgainstSchema(unsafe, { b: 1 }).errors ?? [];

    expect(errors.some((error) => error.message.includes('patternProperties'))).toBe(true);
    // どのキーが追加プロパティか判定できないので、偽の追加プロパティ違反は出さない。
    expect(errors.some((error) => error.path === '/b')).toBe(false);
  });

  it('patternProperties の正規表現本体を message に含めない', () => {
    const unsafe: JsonSchema = { patternProperties: { '^(?=secret)': { type: 'string' } } };
    for (const error of validateAgainstSchema(unsafe, { b: 1 }).errors ?? []) {
      expect(error.message).not.toContain('secret');
    }
  });
});
