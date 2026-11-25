/**
 * JSONPath のフィルタ式 `[?( …)]` の演算コストが予算に計上される。
 *
 * 実時間ではなく、式が評価した要素の読み出し回数（プロパティ getter の呼び出し数）を決定的に数えて
 * pin する。修正前は式 1 項あたりの演算が予算に載らず、読み出し予算に当たる前に数十秒かかった。
 */

import { describe, expect, it } from 'bun:test';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { createPexBudget } from '../budget.js';
import { parsePresentationDefinition } from '../definition.js';
import { evaluatePresentationDefinitionWithBudget } from '../evaluate.js';
import { expressionWeight, MAX_PATH_READS } from '../path-budget.js';

/** `v` の読み出しを数える要素を持つクレーム。 */
function claimsWithCountedArray(length: number): {
  claims: Record<string, unknown>;
  counter: { reads: number };
} {
  const counter = { reads: 0 };
  const arr = Array.from({ length }, (_, i) =>
    Object.defineProperty({}, 'v', {
      enumerable: true,
      get() {
        counter.reads += 1;
        return i;
      },
    }),
  );
  return { claims: { credentialSubject: { arr } }, counter };
}

const SLOW_PATH = `$.credentialSubject.arr[?(@.v>=0&&${Array(200).fill('1').join('+')}<0)]`;

function pdWith(path: string[], fields = 1) {
  return parsePresentationDefinition({
    id: 'pd',
    input_descriptors: [
      {
        id: 'd0',
        constraints: { fields: Array.from({ length: fields }, () => ({ path })) },
      },
    ],
  });
}

describe('フィルタ式の演算コストは JSONPath 予算に計上される', () => {
  it('重い式 × 大きな配列 × 多数のフィールドは予算超過で打ち切られ、不一致（fail-closed）', () => {
    const { claims, counter } = claimsWithCountedArray(1_000);
    const credential: QueryableCredential = { id: 'vc', format: 'dc+sd-jwt', claims };
    const budget = createPexBudget();
    // 先頭 7 候補は式が偽 → 次候補へ。最後の候補は解決できる。修正前は 64 × 7 × 1,000 要素を全て評価した。
    const pd = pdWith([...Array(7).fill(SLOW_PATH), '$.credentialSubject.arr'], 64);

    const matches = evaluatePresentationDefinitionWithBudget(pd, [credential], budget);

    expect(matches).toEqual([]);
    expect(budget.paths.exhausted).toBe(true);
    // 式 1 項の重み分を乗じて計上するため、要素の評価回数は予算 ÷ 式の重みで頭打ちになる
    // （修正前は 64 × 7 × 1,000 = 44.8 万回）。
    expect(counter.reads).toBeLessThanOrEqual(MAX_PATH_READS / (1 + expressionWeight(SLOW_PATH)));
  });

  it('式を含まない path は従来どおり 1 読み出し 1 単位（重み 0）', () => {
    expect(expressionWeight('$.credentialSubject.name')).toBe(0);
    expect(expressionWeight("$.a[?(@.t=='b')]")).toBeGreaterThan(0);
  });

  it('対照: 単純な比較式は十分な予算で完走して一致し、予算を超過しない', () => {
    const { claims } = claimsWithCountedArray(1_000);
    const budget = createPexBudget();
    const matches = evaluatePresentationDefinitionWithBudget(
      pdWith(['$.credentialSubject.arr[?(@.v==7)]']),
      [{ id: 'vc', format: 'dc+sd-jwt', claims }],
      budget,
    );
    expect(matches).toHaveLength(1);
    expect(budget.paths.exhausted).toBe(false);
  });
});
