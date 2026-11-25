/**
 * 長さに比例する処理（文字列インスタンス・オブジェクトキー・`$ref` 文字列）の走査量予算。
 *
 * 実時間ではなく決定的なカウンタ（部分スキーマの読み出し回数・`decodeURIComponent` に渡った
 * 文字列長・走査量の残量）で pin する。修正前は「評価ノード数（≤ 5 万）× 長さ」に比例して
 * 1 KiB〜1 MiB の入力で数十秒停止した。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import {
  type EvaluationBudget,
  MAX_EVALUATIONS,
  MAX_REGEX_STEPS,
  MAX_SCAN_UNITS,
  stringScanUnits,
} from '../internals.js';
import { MAX_REF_LENGTH, resolveRef, resolveRefCharged } from '../ref.js';
import type { JsonSchema, SchemaValidationResult } from '../types.js';
import { validateAgainstSchema } from '../validate.js';

// 修正を外した状態でも（遅くても）失敗として観測できるよう、既定の 5 秒より緩める。
setDefaultTimeout(60_000);

/** ルートに「評価量が上限に達した」必須違反が積まれているか（fail-closed の印）。 */
function hasRootBudgetError(result: SchemaValidationResult): boolean {
  return (result.errors ?? []).some(
    (e) => e.path === '' && e.required && e.message.includes('評価量'),
  );
}

/** `$ref` の 2 分木ファンアウトで `leaf` を 2^depth 回評価させる `$defs` を作る。 */
function fanOutDefs(leaf: JsonSchema, depth: number): Record<string, JsonSchema> {
  const defs: Record<string, JsonSchema> = { leaf, d0: { $ref: '#/$defs/leaf' } };
  for (let i = 1; i <= depth; i += 1) {
    defs[`d${i}`] = { allOf: [{ $ref: `#/$defs/d${i - 1}` }, { $ref: `#/$defs/d${i - 1}` }] };
  }
  return defs;
}

/** 読み出し回数を数える getter を持つ `leaf` スキーマ（`undefined` を返すので検証結果に影響しない）。 */
function countedLeaf(keyword: string, base: JsonSchema = {}) {
  const counter = { reads: 0 };
  const leaf: JsonSchema = { ...base };
  Object.defineProperty(leaf, keyword, {
    enumerable: true,
    get() {
      counter.reads += 1;
      return undefined;
    },
  });
  return { leaf, counter };
}

describe('文字列インスタンスの長さは走査量予算に計上される', () => {
  it('stringScanUnits は deepEqual と同じ `1 + 長さ / 8` 換算', () => {
    expect(stringScanUnits(0)).toBe(1);
    expect(stringScanUnits(7)).toBe(1);
    expect(stringScanUnits(8)).toBe(2);
    expect(stringScanUnits(1_000_000)).toBe(125_001);
  });

  it('1 KiB のスキーマ × 大きな文字列: 文字列を処理する回数は予算で頭打ちになり fail-closed', () => {
    const { leaf, counter } = countedLeaf('minLength');
    const big = 'a'.repeat(50_000);
    const schema = {
      $defs: fanOutDefs(leaf, 15),
      properties: { name: { $ref: '#/$defs/d15' } },
    } as JsonSchema;
    const result = validateAgainstSchema(schema, { name: big });

    // 修正前は 2^15 = 32,768 回すべての leaf で全文字列を走査した（minLength の読み出しは 1 回あたり 3 回）。
    const maxVisits = Math.ceil(MAX_SCAN_UNITS / stringScanUnits(big.length));
    expect(counter.reads).toBeLessThanOrEqual(3 * maxVisits);
    expect(counter.reads).toBeGreaterThan(0);
    expect(result.valid).toBe(false);
    expect(hasRootBudgetError(result)).toBe(true);
  });

  it('予算に収まる現実的な文字列は従来どおり minLength / maxLength / pattern を検証する', () => {
    expect(validateAgainstSchema({ minLength: 2, maxLength: 3 }, 'abc').valid).toBe(true);
    expect(validateAgainstSchema({ maxLength: 3 }, 'abcd').valid).toBe(false);
    // サロゲートペアは 1 文字（コードポイント数）。
    expect(validateAgainstSchema({ maxLength: 2 }, '😀😀').valid).toBe(true);
    expect(validateAgainstSchema({ minLength: 3 }, '😀😀').valid).toBe(false);
    expect(validateAgainstSchema({ pattern: '^a+$' }, 'aaa').valid).toBe(true);
    expect(validateAgainstSchema({ format: 'email' }, 'a@b.example').valid).toBe(true);
    expect(validateAgainstSchema({ format: 'email' }, 'nope').valid).toBe(false);
  });

  it('巨大なオブジェクトキー × 分岐の増幅: キーを処理する回数は予算で頭打ちになり fail-closed', () => {
    const { leaf, counter } = countedLeaf('maxProperties', { additionalProperties: false });
    const key = 'k'.repeat(40_000);
    const schema = { $defs: fanOutDefs(leaf, 15), $ref: '#/$defs/d15' } as JsonSchema;
    const result = validateAgainstSchema(schema, { [key]: 1 });

    // 修正前は 32,768 回すべてで `escapePointer(key)`（O(キー長) の replace ×2）が走った。
    const maxVisits = Math.ceil(MAX_SCAN_UNITS / (1 + stringScanUnits(key.length)));
    expect(counter.reads).toBeLessThanOrEqual(maxVisits);
    expect(counter.reads).toBeGreaterThan(0);
    expect(result.valid).toBe(false);
    expect(hasRootBudgetError(result)).toBe(true);
  });

  it('巨大な必須キー（スキーマ側）× 分岐の増幅: 違反 path の組み立て回数は予算で頭打ちになる', () => {
    const key = 'r'.repeat(40_000);
    const { leaf, counter } = countedLeaf('maxProperties', { required: [key] });
    const schema = { $defs: fanOutDefs(leaf, 15), $ref: '#/$defs/d15' } as JsonSchema;
    const result = validateAgainstSchema(schema, {});

    const maxVisits = Math.ceil(MAX_SCAN_UNITS / stringScanUnits(key.length));
    // leaf の `maxProperties` は予算が尽きた後は読まれない。修正前は 32,768 回すべて読まれた。
    expect(counter.reads).toBeLessThanOrEqual(maxVisits + 1);
    expect(result.valid).toBe(false);
    expect(hasRootBudgetError(result)).toBe(true);
  });
});

describe('$ref の解決コストは評価量予算に計上される', () => {
  const budget = (scanRemaining: number): EvaluationBudget => ({
    remaining: MAX_EVALUATIONS,
    exhausted: false,
    regex: { remaining: MAX_REGEX_STEPS },
    scanRemaining,
  });

  /** 長さちょうど `length` の `$ref`（`#/$defs/<キー>`）とそれを解決できるルートスキーマ。 */
  function rootWithRefOfLength(length: number) {
    const prefix = '#/$defs/';
    const name = 'a'.repeat(length - prefix.length);
    return { ref: prefix + name, root: { $defs: { [name]: { type: 'string' } } } as JsonSchema };
  }

  it('上限ちょうどの長さの参照は解決でき、`1 + 長さ / 8` を走査量から差し引く', () => {
    const { ref, root } = rootWithRefOfLength(MAX_REF_LENGTH);
    const b = budget(MAX_SCAN_UNITS);
    expect(resolveRefCharged(root, ref, b)).toEqual({ type: 'string' });
    expect(b.scanRemaining).toBe(MAX_SCAN_UNITS - stringScanUnits(MAX_REF_LENGTH));
    expect(b.exhausted).toBe(false);
  });

  it('上限を超える長さの参照は参照先があっても解決せず、走査もしない', () => {
    const { ref, root } = rootWithRefOfLength(MAX_REF_LENGTH + 1);
    expect(resolveRef(root, ref)).toEqual({ type: 'string' });
    const b = budget(MAX_SCAN_UNITS);
    expect(resolveRefCharged(root, ref, b)).toBeUndefined();
    expect(b.scanRemaining).toBe(MAX_SCAN_UNITS);
  });

  it('走査量が足りなければ解決せず `exhausted` を立てる', () => {
    const { ref, root } = rootWithRefOfLength(MAX_REF_LENGTH);
    const b = budget(stringScanUnits(MAX_REF_LENGTH) - 1);
    expect(resolveRefCharged(root, ref, b)).toBeUndefined();
    expect(b.exhausted).toBe(true);
    expect(b.scanRemaining).toBe(0);
  });

  it('714 KB 級の再現（巨大キーへの `$ref` × allOf 多重化）: 長い参照は decodeURIComponent に渡らず、違反になる', () => {
    const klen = 300_000;
    const width = 300;
    const key = '~/'.repeat(klen / 4);
    const refSegment = '~0~1'.repeat(klen / 4);
    const defs: Record<string, JsonSchema> = {
      [key]: {},
      d0: { $ref: `#/$defs/${refSegment}` },
    };
    defs.d1 = { allOf: Array.from({ length: width }, () => ({ $ref: '#/$defs/d0' })) };
    const schema = { $defs: defs, $ref: '#/$defs/d1' } as JsonSchema;

    const original = globalThis.decodeURIComponent;
    let maxDecodedLength = 0;
    globalThis.decodeURIComponent = (encoded: string) => {
      maxDecodedLength = Math.max(maxDecodedLength, encoded.length);
      return original(encoded);
    };
    let result: SchemaValidationResult;
    try {
      result = validateAgainstSchema(schema, 1);
    } finally {
      globalThis.decodeURIComponent = original;
    }

    // 修正前は 30 万文字のセグメントが評価のたびに（width 回）デコードされた。
    expect(maxDecodedLength).toBeLessThanOrEqual(MAX_REF_LENGTH);
    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.message.includes('$ref を解決できません'))).toBe(true);
  });
});
