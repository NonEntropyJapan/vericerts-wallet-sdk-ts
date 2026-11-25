/**
 * PEx 評価の予算・互換性の回帰テスト。
 *
 * - `field.path` の JSONPath 評価に走査量予算があり、`$..*..*..*..*` が固まらず fail-closed になる。
 * - `filter.pattern` は非 `u`（ECMA-262 Annex B）で評価され、従来有効だった構文が不一致にならない。
 *   後方参照・先読み・構文不正は引き続き不一致（線形時間エンジンの安全性は変えない）。
 */

import { describe, expect, it } from 'bun:test';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { ErrorCodes, type VericertsError } from '../../errors.js';
import { createPexBudget, type PexBudget } from '../budget.js';
import { parsePresentationDefinition } from '../definition.js';
import {
  evaluatePresentationDefinition,
  evaluatePresentationDefinitionWithBudget,
} from '../evaluate.js';

function definitionWith(field: Record<string, unknown>) {
  return parsePresentationDefinition({
    id: 'pd-1',
    input_descriptors: [{ id: 'd1', constraints: { fields: [field] } }],
  });
}

function credentialWith(claims: Record<string, unknown>, id = 'vc-1'): QueryableCredential {
  return { id, format: 'dc+sd-jwt', claims };
}

/** 深さ `depth` の入れ子（各階層に子 object と 1 要素配列を持つ）。 */
function deepClaims(depth: number): Record<string, unknown> {
  let node: Record<string, unknown> = { leaf: 1 };
  for (let i = 0; i < depth; i += 1) {
    node = { a: node, b: [node.leaf ?? 1] };
  }
  return { credentialSubject: node, name: 'Alice' };
}

/** 深さ 8 で `$..*..*..*..*` は約 7,000 回の読み出しを要する（深さ加算の計上後は約 5 万。既定予算の範囲内で完走する規模）。 */
const HEAVY_PATH = '$..*..*..*..*';
const CLAIMS = deepClaims(8);

/** JSONPath 読み出し予算だけを絞った予算（実物の `MAX_PATH_READS` を踏ませると評価が秒単位になるため注入する）。 */
function budgetWithPathReads(remaining: number): PexBudget {
  const budget = createPexBudget();
  budget.paths.remaining = remaining;
  return budget;
}

/** 予算が足りていれば `HEAVY_PATH` は完走して一致する。打ち切りが予算由来であることの対照に使う。 */
const READS_FOR_HEAVY_PATH = 200_000;
const TIGHT_READS = 1_000;

describe('field.path の JSONPath 評価量予算', () => {
  it('対照: 十分な予算なら `$..*..*..*..*` は完走して一致し、打ち切り予算より多く読む', () => {
    const budget = budgetWithPathReads(READS_FOR_HEAVY_PATH);
    const matches = evaluatePresentationDefinitionWithBudget(
      definitionWith({ path: [HEAVY_PATH] }),
      [credentialWith(CLAIMS)],
      budget,
    );
    expect(matches).toHaveLength(1);
    expect(budget.paths.exhausted).toBe(false);
    expect(READS_FOR_HEAVY_PATH - budget.paths.remaining).toBeGreaterThan(TIGHT_READS);
  });

  it('`$..*..*..*..*` は予算超過で打ち切られ、不一致になる', () => {
    // 実時間ではなく読み出し回数の予算で pin する（負荷の高い CI でも結果が変わらない）。
    const budget = budgetWithPathReads(TIGHT_READS);
    const matches = evaluatePresentationDefinitionWithBudget(
      definitionWith({ path: [HEAVY_PATH] }),
      [credentialWith(CLAIMS)],
      budget,
    );
    expect(matches).toEqual([]);
    expect(budget.paths.exhausted).toBe(true);
  });

  it('予算超過は optional でも不一致（評価不能を「値なし」として通さない）', () => {
    const budget = budgetWithPathReads(TIGHT_READS);
    const matches = evaluatePresentationDefinitionWithBudget(
      definitionWith({ path: [HEAVY_PATH], optional: true }),
      [credentialWith(CLAIMS)],
      budget,
    );
    expect(matches).toEqual([]);
    expect(budget.paths.exhausted).toBe(true);
  });

  it('予算を使い切った後は、単純な path でも同じ呼び出し内では不一致になる（共有予算）', () => {
    const pd = parsePresentationDefinition({
      id: 'pd-1',
      input_descriptors: [
        { id: 'heavy', constraints: { fields: [{ path: [HEAVY_PATH] }] } },
        { id: 'light', constraints: { fields: [{ path: ['$.name'] }] } },
      ],
    });
    // 対照: 予算が足りれば light は単独で一致する。
    const light = parsePresentationDefinition({
      id: 'pd-1',
      input_descriptors: [{ id: 'light', constraints: { fields: [{ path: ['$.name'] }] } }],
    });
    expect(
      evaluatePresentationDefinitionWithBudget(
        light,
        [credentialWith(CLAIMS)],
        budgetWithPathReads(TIGHT_READS),
      ),
    ).toHaveLength(1);

    const budget = budgetWithPathReads(TIGHT_READS);
    const matches = evaluatePresentationDefinitionWithBudget(pd, [credentialWith(CLAIMS)], budget);
    expect(matches).toEqual([]);
    expect(budget.paths.exhausted).toBe(true);
  });

  it('通常の path は従来どおり解決する（フィルタ式・再帰下降・複数候補）', () => {
    const credential = credentialWith({
      credentialSubject: { name: 'Alice', items: [{ t: 'a' }, { t: 'b' }] },
    });
    const run = (field: Record<string, unknown>) =>
      evaluatePresentationDefinition(definitionWith(field), [credential]);
    expect(run({ path: ['$.credentialSubject.name'] })).toHaveLength(1);
    expect(run({ path: ['$..t'], filter: { type: 'string', const: 'a' } })).toHaveLength(1);
    expect(
      run({ path: ["$.credentialSubject.items[?(@.t=='b')].t"], filter: { type: 'string' } }),
    ).toHaveLength(1);
    expect(run({ path: ['$.missing', '$.credentialSubject.name'] })[0]?.matchedClaims).toEqual([
      '$.credentialSubject.name',
    ]);
    expect(run({ path: ['$.missing'] })).toEqual([]);
    expect(run({ path: ['$.missing'], optional: true })).toHaveLength(1);
  });

  it('凍結されたクレームでも解決でき、元のクレームは変更されない', () => {
    const claims = Object.freeze({
      credentialSubject: Object.freeze({ name: 'Alice', tags: Object.freeze(['x', 'y']) }),
    });
    const matches = evaluatePresentationDefinition(
      definitionWith({ path: ['$.credentialSubject.tags[1]'], filter: { type: 'string' } }),
      [credentialWith(claims)],
    );
    expect(matches).toHaveLength(1);
    expect(claims.credentialSubject.tags).toEqual(['x', 'y']);
  });

  it('過大な path / 候補数 / fields 数は 8030 で拒否する', () => {
    const expectRejected = (raw: Record<string, unknown>) => {
      try {
        parsePresentationDefinition(raw);
        throw new Error('should have thrown');
      } catch (error) {
        expect((error as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
      }
    };
    const descriptor = (fields: unknown[]) => ({
      id: 'pd-1',
      input_descriptors: [{ id: 'd1', constraints: { fields } }],
    });
    expectRejected(descriptor([{ path: [`$.${'a'.repeat(600)}`] }]));
    expectRejected(descriptor([{ path: Array.from({ length: 9 }, (_, i) => `$.a${i}`) }]));
    expectRejected(descriptor(Array.from({ length: 65 }, (_, i) => ({ path: [`$.a${i}`] }))));
  });
});

describe('filter.pattern は Annex B 互換で評価する', () => {
  const matchesPattern = (pattern: string, value: string): boolean => {
    const matches = evaluatePresentationDefinition(
      definitionWith({ path: ['$.v'], filter: { type: 'string', pattern } }),
      [credentialWith({ v: value })],
    );
    return matches.length === 1;
  };

  it.each([
    ['^did\\:web\\:example\\.com$', 'did:web:example.com'],
    ['^[\\w-.]+@example\\.com$', 'a.b@example.com'],
    ['^\\d{3}\\-\\d{4}$', '123-4567'],
    ['^a{$', 'a{'],
    ['^[a-z]+\\@x$', 'abc@x'],
  ])('従来有効だった %s が %s に一致する', (pattern, value) => {
    expect(new RegExp(pattern).test(value)).toBe(true);
    expect(matchesPattern(pattern, value)).toBe(true);
  });

  it('一致しない値は不一致のまま', () => {
    expect(matchesPattern('^did\\:web\\:example\\.com$', 'did:web:other.com')).toBe(false);
    expect(matchesPattern('^[\\w-.]+@example\\.com$', 'a b@example.com')).toBe(false);
  });

  it('後方参照・先読み・構文不正は引き続き不一致（線形時間エンジンの安全性は維持）', () => {
    expect(matchesPattern('^(a)\\1$', 'aa')).toBe(false);
    expect(matchesPattern('^(?=a)a$', 'a')).toBe(false);
    expect(matchesPattern('(', 'a')).toBe(false);
  });

  it('ReDoS パターンは非 u モードでも固まらない', () => {
    const startedAt = performance.now();
    expect(matchesPattern('^(a*){10}b', 'a'.repeat(10_000))).toBe(false);
    expect(performance.now() - startedAt).toBeLessThan(2_000);
  });
});
