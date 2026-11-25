/**
 * `pattern` / `patternProperties` / `uniqueItems` の DoS 回帰テスト（旧）。
 *
 * - `pattern` はネイティブ `RegExp` ではなく線形時間エンジン（`safe-regex`）で評価する。静的検知を
 *   すり抜けた `(a*){10}b`（11 文字）等が、入力が長くても固まらないこと。
 * - 評価できない構文・上限超過は例外にせず必須違反として報告し、`not` の中でも fail-open にならないこと。
 * - `uniqueItems` は O(n) で、走査量が評価量予算に計上されること。
 */

import { describe, expect, it } from 'bun:test';
import type { JsonSchema } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

function timed<T>(fn: () => T): { result: T; elapsedMs: number } {
  const startedAt = performance.now();
  const result = fn();
  return { result, elapsedMs: performance.now() - startedAt };
}

describe('validateAgainstSchema — pattern は線形時間で評価する', () => {
  it.each([
    ['^(a*){10}b', 'a'.repeat(40)],
    ['^(?:a+){10}$', `${'a'.repeat(40)}!`],
    ['^(a+){30}$', `${'a'.repeat(40)}!`],
    ['^(?:a?){28}a{28}$', 'a'.repeat(27)],
    ['^(a+)+$', `${'a'.repeat(40)}!`],
    ['(a|a)*b', 'a'.repeat(40)],
  ])('%s は 1 秒未満で不一致の違反を返す', (pattern, value) => {
    const { result, elapsedMs } = timed(() => validateAgainstSchema({ pattern }, value));
    expect(result.valid).toBe(false);
    expect(elapsedMs).toBeLessThan(1_000);
  });

  it('パターンの意味は保たれる（安全な形は従来どおり一致 / 不一致を判定する）', () => {
    expect(validateAgainstSchema({ pattern: '^(a|b)+$' }, 'abba').valid).toBe(true);
    expect(validateAgainstSchema({ pattern: '^(a|b)+$' }, 'abc').valid).toBe(false);
    expect(validateAgainstSchema({ pattern: '^(a*){10}b' }, 'aaab').valid).toBe(true);
  });

  it('後方参照・先読みは評価せず、必須違反として報告する（message に本体を含めない）', () => {
    for (const pattern of ['(a)\\1', '(?=secret)', '(?<!x)y']) {
      const result = validateAgainstSchema({ pattern }, 'secret');
      expect(result.valid).toBe(false);
      for (const error of result.errors ?? []) {
        expect(error.message).not.toContain('secret');
      }
    }
  });

  it('評価量の上限を超える pattern は not の内側でも適合扱い（fail-open）にならない', () => {
    // `{1000}` の入れ子は展開サイズ上限を超える。`not` の中の違反は破棄されるため、
    // 上限超過をルートの必須違反に格上げしていないと「not を満たした」ことになってしまう。
    const schema: JsonSchema = { not: { pattern: '((a{1000}){1000}){1000}' } };
    const result = validateAgainstSchema(schema, 'a');
    expect(result.valid).toBe(false);
    expect(result.errors?.some((error) => error.path === '' && error.required)).toBe(true);
  });

  it('1 回の検証で共有する評価ステップ予算を使い切ると以降を fail-closed にする', () => {
    const schema: JsonSchema = {
      type: 'array',
      items: { type: 'string', pattern: '^(?:[a-z]{1,1000}){3}$' },
    };
    const instance = Array.from({ length: 10 }, () => 'a'.repeat(1_000));
    const { result, elapsedMs } = timed(() => validateAgainstSchema(schema, instance));
    expect(result.valid).toBe(false);
    expect(elapsedMs).toBeLessThan(3_000);
  });

  it('patternProperties の攻撃パターンも固まらず、一致しないキーを追加プロパティとして拒否する', () => {
    const schema: JsonSchema = {
      patternProperties: { '^(a*){10}b': { type: 'string' } },
      additionalProperties: false,
    };
    const key = 'a'.repeat(40);
    const { result, elapsedMs } = timed(() => validateAgainstSchema(schema, { [key]: 'x' }));
    expect(result.errors?.map((error) => error.path)).toEqual([`/${key}`]);
    expect(elapsedMs).toBeLessThan(1_000);
    expect(validateAgainstSchema(schema, { [`${key}b`]: 'x' }).valid).toBe(true);
  });
});

describe('validateAgainstSchema — uniqueItems は O(n)', () => {
  it('10 万要素の重複なし配列を数百 ms 以内に判定する', () => {
    const instance = Array.from({ length: 100_000 }, (_, i) => i);
    const { result, elapsedMs } = timed(() =>
      validateAgainstSchema({ uniqueItems: true }, instance),
    );
    expect(result.valid).toBe(true);
    expect(elapsedMs).toBeLessThan(1_000);
  });

  it('重複・キー順違いのオブジェクト重複・ネスト配列の重複を検出する', () => {
    const unique = { uniqueItems: true };
    expect(validateAgainstSchema(unique, [1, 2, 1]).valid).toBe(false);
    expect(
      validateAgainstSchema(unique, [
        { a: 1, b: [1, 2] },
        { b: [1, 2], a: 1 },
      ]).valid,
    ).toBe(false);
    expect(
      validateAgainstSchema(unique, [
        [1, [2]],
        [1, [2]],
      ]).valid,
    ).toBe(false);
    expect(validateAgainstSchema(unique, [1, 1.0]).valid).toBe(false);
    expect(validateAgainstSchema(unique, [0, -0]).valid).toBe(false);
  });

  it('型や順序が違えば別要素として扱う', () => {
    const unique = { uniqueItems: true };
    expect(validateAgainstSchema(unique, [1, '1', true, null, [1], { a: 1 }]).valid).toBe(true);
    expect(
      validateAgainstSchema(unique, [
        [1, 2],
        [2, 1],
      ]).valid,
    ).toBe(true);
    expect(validateAgainstSchema(unique, [{ a: 1 }, { a: 1, b: 1 }]).valid).toBe(true);
    expect(validateAgainstSchema(unique, ['a,b', ['a', 'b']]).valid).toBe(true);
  });

  it('走査量が評価量予算を超える配列は黙って通さず必須違反にする', () => {
    // 数値 1 要素あたり約 7 走査量 × 90 万要素 > MAX_SCAN_UNITS で予算超過。
    const instance = Array.from({ length: 900_000 }, (_, i) => i);
    const result = validateAgainstSchema({ uniqueItems: true }, instance);
    expect(result.valid).toBe(false);
    expect(result.errors?.some((error) => error.required)).toBe(true);
  });

  it('JSON 値でない要素（bigint）は例外を投げず違反として報告する', () => {
    const result = validateAgainstSchema({ uniqueItems: true }, [1n, 2n]);
    expect(result.valid).toBe(false);
  });
});
