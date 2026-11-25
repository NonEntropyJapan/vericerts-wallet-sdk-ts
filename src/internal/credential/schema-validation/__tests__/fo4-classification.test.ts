/**
 * FO-4 の適用境界の回帰テスト（critical 3 / critical 4）。
 *
 * FO-4 の対象は `credentialSchema` の任意属性のバリデーション違反である。
 *
 * `validateAgainstSchema` の `SchemaError.required` は、そのまま `applySchemaViolations` の
 * fail-open / fail-closed 判断になる。`json-schema/__tests__/required-classification.test.ts`
 * が分類そのものを固定するのに対し、本ファイルは**その分類が FO-4 の判断へどう落ちるか**を
 * 固定する。必須属性の違反は `valid: false` になる。
 *
 * 検証内容:
 * - ルートの構造違反（critical 3）は `valid: false` + 警告なし。
 * - `oneOf` で表現した必須構造の違反（critical 4）は `valid: false` + 警告なし。
 * - 任意属性のみの違反は `valid: true` + `warnings: ['schema_optional_invalid']` のまま。
 */

import { describe, expect, it } from 'bun:test';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../failsafe/index.js';
import { createFailOpenWindow } from '../../../failsafe-policy/index.js';
import type { JsonSchema, SchemaFailSafeResult } from '../../json-schema/index.js';
import { validateAgainstSchema } from '../../json-schema/index.js';
import { applySchemaViolations } from '../fail-safe.js';

/**
 * スキーマ検証から FO-4 適用までを 1 回で通す。
 *
 * 本ファイルの関心は「必須 / 任意の分類が FO-4 の判断へどう落ちるか」なので、警告通過の成立条件
 * （同意 + 監査記録先）と時間上限は常に満たした状態で呼ぶ。ウィンドウは呼び出しごとに
 * 新しくして、モジュール既定の共有ウィンドウや他テストの計時に左右されないようにする。
 */
async function validate(schema: JsonSchema, instance: unknown): Promise<SchemaFailSafeResult> {
  return await applySchemaViolations(
    'urn:test:schema',
    0,
    validateAgainstSchema(schema, instance),
    {
      requestConsent: () => true,
      onPolicyEvent: () => {},
      failOpenWindow: createFailOpenWindow(),
    },
  );
}

/** `name` が必須、`nickname` が任意のスキーマ。 */
const PERSON: JsonSchema = {
  type: 'object',
  required: ['name'],
  properties: {
    name: { type: 'string', minLength: 1 },
    nickname: { type: 'string', maxLength: 8 },
  },
};

describe('FO-4 は必須制約の違反を警告通過させない', () => {
  it('credentialSubject の型がスキーマと矛盾すれば valid: false（critical 3）', async () => {
    const result = await validate(PERSON, ['totally', 'wrong', 'shape']);

    expect(result.valid).toBe(false);
    expect(result.schemaAvailable).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it('oneOf で表現した必須構造の違反も valid: false（critical 4）', async () => {
    const schema: JsonSchema = { oneOf: [{ required: ['a'] }, { required: ['b'] }] };
    const result = await validate(schema, { c: 1 });

    expect(result.valid).toBe(false);
    expect(result.warnings).toEqual([]);
  });

  it('required キーワードの違反は従来どおり valid: false', async () => {
    const result = await validate(PERSON, { nickname: 'たろ' });

    expect(result.valid).toBe(false);
    expect(result.warnings).toEqual([]);
  });
});

describe('FO-4 は任意属性の違反を警告通過させ続ける', () => {
  it('任意属性のみの違反は valid: true + schema_optional_invalid', async () => {
    const result = await validate(PERSON, { name: '山田太郎', nickname: 'ながすぎる愛称です' });

    expect(result.valid).toBe(true);
    expect(result.schemaAvailable).toBe(true);
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-4']]);
    // 通過させても違反内容は呼び出し側が確認できるよう残す。
    expect(result.errors?.map((error) => error.path)).toEqual(['/nickname']);
  });

  it('スキーマに適合する入力は警告も違反も出さない', async () => {
    const result = await validate(PERSON, { name: '山田太郎', nickname: 'たろ' });

    expect(result).toEqual({ valid: true, schemaAvailable: true, warnings: [] });
  });

  it('patternProperties に一致するキーで偽の違反を出さない（major 2）', async () => {
    const schema: JsonSchema = {
      type: 'object',
      properties: { name: { type: 'string' } },
      patternProperties: { '^ext_': { type: 'string' } },
      additionalProperties: false,
    };

    expect(await validate(schema, { name: '山田太郎', ext_locale: 'ja-JP' })).toEqual({
      valid: true,
      schemaAvailable: true,
      warnings: [],
    });
  });
});
