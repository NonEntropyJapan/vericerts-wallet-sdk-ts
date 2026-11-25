/**
 * JSONPath フィルタ式の `+`（文字列連結）の拒否（予算の迂回）。
 *
 * `@.a+@.a+…` は 1 回の評価でオペランド長 × 項数の文字列を確保するが、文字列は primitive のため読み出し予算に
 * 現れない。式の構文木を許可リストで検査し、文字列になり得る `+` を含む式は評価前に拒否する。
 * 実時間・RSS ではなく、「連結を評価していれば一致する」クレームが**一致しないこと**で pin する（決定的）。
 */

import { describe, expect, it } from 'bun:test';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { createPexBudget } from '../budget.js';
import { parsePresentationDefinition } from '../definition.js';
import { evaluatePresentationDefinitionWithBudget } from '../evaluate.js';

function evaluate(path: string, claims: Record<string, unknown>) {
  const pd = parsePresentationDefinition({
    id: 'pd',
    input_descriptors: [{ id: 'd0', constraints: { fields: [{ path: [path] }] } }],
  });
  const credential: QueryableCredential = { id: 'vc', format: 'dc+sd-jwt', claims };
  const matches = evaluatePresentationDefinitionWithBudget(pd, [credential], createPexBudget());
  return { matches: matches.length };
}

/** 末尾が `q` の長い文字列を 1 つ持つクレーム（`>'a'` の比較は先頭 `x` で成立する）。 */
const claimsOfLength = (length: number): Record<string, unknown> => ({
  s: [{ a: `${'x'.repeat(length - 1)}q` }],
});

describe('フィルタ式の文字列連結 + は評価しない', () => {
  // [文字列長, 項数]。項数は path 長上限（512 文字）の範囲で変える。いずれも「連結すれば大量確保」の形。
  const shapes: [number, number][] = [
    [1_000_000, 120],
    [100_000, 120],
    [4_000, 30],
    [10, 2],
  ];

  for (const [length, terms] of shapes) {
    it(`文字列 ${length} 文字 × ${terms} 項の @.a+@.a+… は評価せず不一致`, () => {
      const claims = claimsOfLength(length);
      // 対照: 同じクレームで連結なし（1 項）なら評価され一致する（'x…' > 'a'）。
      expect(evaluate("$.s[?(@.a>'a')]", claims).matches).toBe(1);
      // 連結を評価していれば同じ比較が成立して 1 件一致する。検査で拒否されるので 0 件。
      const path = `$.s[?(${Array(terms).fill('@.a').join('+')}>'a')]`;
      expect(evaluate(path, claims).matches).toBe(0);
    });
  }

  it.each([
    ["$.s[?(@.a+'x'=='qx')]"],
    ["$.s[?('x'+@.a=='xq')]"],
    ["$.s[?(@.a+@.a=='qq')]"],
    ["$.s[?('a'+'b'=='ab')]"],
    ["$.s[?(@.a+1=='q1')]"],
    ["$.s[?((@.a+@.a)+(@.a+@.a)=='qqqq')]"],
  ])('文字列になり得る + を含む %s は不一致（解決できない）', (path) => {
    expect(evaluate(path, { s: [{ a: 'q' }] }).matches).toBe(0);
  });

  it('数値定数どうしの + は従来どおり評価できる（200 項の定数式も含む）', () => {
    const claims = { s: [{ v: 2 }] };
    expect(evaluate('$.s[?(@.v==(1+1))]', claims).matches).toBe(1);
    expect(evaluate('$.s[?(@.v==1+1)]', claims).matches).toBe(1);
    expect(evaluate('$.s[?(@.v==-(1)+3)]', claims).matches).toBe(1);
    expect(evaluate(`$.s[?(@.v>=0&&${Array(150).fill('1').join('+')}>0)]`, claims).matches).toBe(1);
  });

  it('+ 以外の算術・比較・論理は従来どおり（文字列を確保しない）', () => {
    const claims = { s: [{ v: 5, a: 'q' }] };
    expect(evaluate('$.s[?(@.v-1==4)]', claims).matches).toBe(1);
    expect(evaluate("$.s[?(@.v*2==10 && @.a=='q')]", claims).matches).toBe(1);
    expect(evaluate('$.s[?(@.v%2==1)]', claims).matches).toBe(1);
  });
});
