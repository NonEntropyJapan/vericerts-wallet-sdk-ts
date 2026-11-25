/**
 * バリデータのハードニング回帰テスト（C6 / M4）。
 *
 * 検証内容:
 * - C6: `anyOf` / `oneOf` / `not` の分岐評価が指数爆発しないこと。`MAX_DEPTH` だけでは
 *   枝分かれを止められず、約 120 バイトのスキーマでプロセスがハングした（DoS）。
 *   評価ノード数の総量上限で打ち切り、**適合扱いにせず違反として報告する**ことを保証する。
 * - M4: Draft 2020-12 の `$ref` は兄弟キーワードを上書きしない。参照先の検証後に同ノードの
 *   他キーワードも評価されること（silent under-validation の防止）を保証する。
 */

import { describe, expect, it } from 'bun:test';
import { parseJsonWithoutPrototype } from '../../../prototype-safety/parse-json.js';
import type { JsonSchema } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

/** 検証にかかった時間（ミリ秒）と結果を返す。 */
function timed(schema: JsonSchema, instance: unknown) {
  const startedAt = performance.now();
  const result = validateAgainstSchema(schema, instance);
  return { result, elapsedMs: performance.now() - startedAt };
}

describe('validateAgainstSchema — 分岐評価の指数爆発を打ち切る（C6）', () => {
  it('自己参照 anyOf の 2 分岐スキーマでハングしない', () => {
    // 修正前はこの約 120 バイトのスキーマで 2 分以上停止しなかった（2^深さ の評価）。
    const schema: JsonSchema = {
      $defs: { x: { anyOf: [{ $ref: '#/$defs/x' }, { $ref: '#/$defs/x' }] } },
      $ref: '#/$defs/x',
    };
    const { result, elapsedMs } = timed(schema, { a: 1 });

    expect(result.valid).toBe(false);
    expect(elapsedMs).toBeLessThan(5_000);
  });

  it('打ち切りは fail-open にせず、必須属性違反として報告する', () => {
    const schema: JsonSchema = {
      $defs: { x: { anyOf: [{ $ref: '#/$defs/x' }, { $ref: '#/$defs/x' }] } },
      $ref: '#/$defs/x',
    };
    const errors = validateAgainstSchema(schema, {}).errors ?? [];

    // ルートに 1 件は required: true の違反が残り、FO-4 の警告通過に落とせない。
    expect(errors.some((error) => error.required && error.path === '')).toBe(true);
  });

  it('oneOf / not の分岐でも打ち切る', () => {
    const oneOf: JsonSchema = {
      $defs: { x: { oneOf: [{ $ref: '#/$defs/x' }, { $ref: '#/$defs/x' }] } },
      $ref: '#/$defs/x',
    };
    const not: JsonSchema = {
      $defs: { x: { not: { anyOf: [{ $ref: '#/$defs/x' }, { $ref: '#/$defs/x' }] } } },
      $ref: '#/$defs/x',
    };
    expect(timed(oneOf, {}).elapsedMs).toBeLessThan(5_000);
    expect(timed(not, {}).elapsedMs).toBeLessThan(5_000);
    expect(validateAgainstSchema(oneOf, {}).valid).toBe(false);
    expect(validateAgainstSchema(not, {}).valid).toBe(false);
  });

  it('打ち切りメッセージにインスタンスの値を含めない', () => {
    const secret = 'my-social-security-number-123456';
    const schema: JsonSchema = {
      $defs: { x: { anyOf: [{ $ref: '#/$defs/x' }, { $ref: '#/$defs/x' }] } },
      $ref: '#/$defs/x',
    };
    for (const error of validateAgainstSchema(schema, { ssn: secret }).errors ?? []) {
      expect(error.message).not.toContain(secret);
    }
  });

  it('現実的な規模のスキーマは総量上限に達せず適合する', () => {
    // 100 プロパティ × 3 要素の配列 = 上限（MAX_EVALUATIONS）に対し十分小さい。
    const properties: Record<string, unknown> = {};
    const instance: Record<string, unknown> = {};
    for (let i = 0; i < 100; i += 1) {
      properties[`p${i}`] = { type: 'array', items: { type: 'string' } };
      instance[`p${i}`] = ['a', 'b', 'c'];
    }
    expect(validateAgainstSchema({ type: 'object', properties }, instance).valid).toBe(true);
  });
});

describe('validateAgainstSchema — $ref の兄弟キーワードを捨てない（M4）', () => {
  const schema: JsonSchema = {
    $defs: { base: { type: 'object', properties: { a: { type: 'string' } } } },
    $ref: '#/$defs/base',
    required: ['a'],
  };

  it('$ref と同階層の required を評価する', () => {
    const result = validateAgainstSchema(schema, {});
    expect(result.valid).toBe(false);
    expect(result.errors?.some((error) => error.path === '/a' && error.required)).toBe(true);
  });

  it('参照先と兄弟キーワードの双方に適合すれば適合する', () => {
    expect(validateAgainstSchema(schema, { a: 'x' }).valid).toBe(true);
  });

  it('参照先の制約も従来どおり評価する', () => {
    const result = validateAgainstSchema(schema, { a: 1 });
    expect(result.valid).toBe(false);
    expect(result.errors?.some((error) => error.path === '/a')).toBe(true);
  });

  it('$ref と同階層の additionalProperties を評価する', () => {
    // Draft 2020-12 の `additionalProperties` は**同一スキーマオブジェクト**の `properties`
    // だけを参照する（`$ref` 先の `properties` は対象外）。ここでは兄弟キーワードが
    // 捨てられずに評価されること自体を確認する。
    const withAdditional: JsonSchema = {
      $defs: { base: { type: 'object' } },
      $ref: '#/$defs/base',
      properties: { a: { type: 'string' } },
      additionalProperties: false,
    };
    expect(validateAgainstSchema(withAdditional, { a: 'x' }).valid).toBe(true);
    const result = validateAgainstSchema(withAdditional, { a: 'x', extra: 1 });
    expect(result.valid).toBe(false);
    expect(result.errors?.some((error) => error.path === '/extra')).toBe(true);
  });

  it('プロパティ配下の $ref でも兄弟キーワードが効く', () => {
    const nested: JsonSchema = {
      $defs: { name: { type: 'string' } },
      type: 'object',
      properties: { name: { $ref: '#/$defs/name', minLength: 3 } },
    };
    expect(validateAgainstSchema(nested, { name: 'abc' }).valid).toBe(true);
    expect(validateAgainstSchema(nested, { name: 'ab' }).valid).toBe(false);
  });
});

describe('validateAgainstSchema — 不正な type 配列でも例外を投げない', () => {
  /**
   * Issuer 配布のリモートスキーマは `parseJsonWithoutPrototype` を通るため、オブジェクト値は
   * `Object.prototype` を継承しない（＝`toString` / `valueOf` を持たない）。`type` 配列の要素を
   * 検証せずに `join` すると暗黙の `ToPrimitive` が `TypeError: No default value` になり、
   * 「例外を投げず違反を `errors` にまとめて返す」契約が破れて 3015 / 3016 / FO-3 の fail-safe
   * 分岐まで素通りしていた。**素のオブジェクトリテラルでは再現しない**ため、必ずパース境界を通す。
   */
  function parseSchema(json: string): JsonSchema {
    return parseJsonWithoutPrototype(json) as JsonSchema;
  }

  it('非文字列要素を含む type 配列で TypeError にならず違反として報告する', () => {
    const schema = parseSchema('{"type":"object","properties":{"a":{"type":["number",{"x":1}]}}}');
    const result = validateAgainstSchema(schema, { a: 's' });

    expect(result.valid).toBe(false);
    const error = result.errors?.find((e) => e.path === '/a');
    expect(error?.message).toContain('number');
    // 非文字列要素の混入はスキーマ不正として文言で示す（要素自体は文字列化しない）。
    expect(error?.message).toContain('文字列でない要素');
  });

  it('文字列要素のいずれかに一致すれば従来どおり適合する', () => {
    const schema = parseSchema('{"type":"object","properties":{"a":{"type":["number",{"x":1}]}}}');
    expect(validateAgainstSchema(schema, { a: 1 }).valid).toBe(true);
  });

  it('type 配列に文字列要素が 1 つも無い場合もスキーマ不正として報告する', () => {
    const schema = parseSchema('{"type":"object","properties":{"a":{"type":[{"x":1}]}}}');
    const result = validateAgainstSchema(schema, { a: 's' });

    expect(result.valid).toBe(false);
    expect(result.errors?.find((e) => e.path === '/a')?.message).toContain('スキーマとして不正');
  });
});
