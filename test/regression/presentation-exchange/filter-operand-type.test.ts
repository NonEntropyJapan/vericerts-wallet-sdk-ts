/**
 * PEx フィルタ式 `[?( … )]` の型違反オペランドは、その要素だけを不一致にする回帰テスト。
 *
 * 欠陥時の挙動: `guarded-eval.ts` はオペランドが配列・オブジェクト・長い文字列（数値化）のとき例外を投げ、
 * `jsonpath-plus` はそれを要素単位で握らず `JSONPath()` 全体を中断する。`resolveJsonPath` はこれを「解決できなかった」
 * に倒すため、配列の他の要素が条件を満たしていても path 全体が値なしになり、一致していた VC が候補から消える
 * （W3C VC の `type` 配列や、入れ子オブジェクトを要素に持つ配列で起こる）。
 *
 * fail-closed は保つ: 型違反の要素は否定（`!`）を挟んでも一致に転じない。スクリプト式 `[( … )]` は
 * 従来どおり path 全体を解決不能にする（結果がプロパティ名として使われるため、偽値に倒すと別キーを読む）。
 *
 * 既知の限界: 式全体を括弧で囲んだフィルタ（`[?((A))]` / `[?((A) || (B))]`）は jsonpath-plus の仕様上スクリプト式と
 * 区別できないため、型違反の要素があると従来どおり path 全体が解決不能になる（一致なしに倒れる fail-closed）。
 */

import { describe, expect, it } from 'bun:test';
import { parsePresentationDefinition } from '../../../src/internal/presentation-exchange/definition.js';
import { evaluatePresentationDefinition } from '../../../src/internal/presentation-exchange/evaluate.js';

function matchCount(
  path: string,
  claims: Record<string, unknown>,
  filter?: Record<string, unknown>,
): number {
  const field = filter === undefined ? { path: [path] } : { path: [path], filter };
  const pd = parsePresentationDefinition({
    id: 'pd',
    input_descriptors: [{ id: 'd0', constraints: { fields: [field] } }],
  });
  return evaluatePresentationDefinition(pd, [{ id: 'vc', format: 'dc+sd-jwt', claims }]).length;
}

const longString = 'long'.repeat(40);

describe('フィルタ式の型違反オペランドは要素単位で不一致にする', () => {
  it.each([
    ['配列要素が先頭', { items: [{ type: ['a'] }, { type: 'b' }] }],
    ['配列要素が末尾', { items: [{ type: 'b' }, { type: ['a'] }] }],
  ])('regression: type 配列の要素があっても一致する要素は残る（%s）', (_, claims) => {
    expect(matchCount('$.items[?(@.type == "b")]', claims)).toBe(1);
  });

  it.each([
    ['オブジェクト・長い文字列が先頭', { d: [{ x: { y: 1 } }, { x: longString }, { x: 3 }] }],
    ['一致要素が先頭', { d: [{ x: 3 }, { x: { y: 1 } }, { x: longString }] }],
  ])('regression: オブジェクト・長い文字列の要素があっても数値比較で一致する要素は残る（%s）', (_, claims) => {
    expect(matchCount('$.d[?(@.x == 3)]', claims)).toBe(1);
  });

  it('regression: 型違反の要素は否定を挟んでも一致に転じない（fail-closed）', () => {
    // 型違反の要素だけなら一致なし。
    expect(matchCount('$.items[?(!(@.type == "b"))]', { items: [{ type: ['a'] }] })).toBe(0);
    expect(matchCount('$.d[?(!(@.x < 3))]', { d: [{ x: longString }] })).toBe(0);
    // 型違反の要素（id: 'a'）は飛ばされ、条件を満たす要素（id: 'c'）が先頭の結果になる。
    const claims = {
      items: [
        { type: ['a'], id: 'a' },
        { type: 'c', id: 'c' },
      ],
    };
    expect(
      matchCount('$.items[?(!(@.type == "b"))].id', claims, { type: 'string', const: 'c' }),
    ).toBe(1);
  });

  it('regression: スクリプト式 [( … )] の型違反は従来どおり path 全体を解決不能にする', () => {
    // 偽値に倒すとキー `false` を読んでしまう。
    expect(matchCount('$.s[(@.o == 1)]', { s: { o: ['x'], false: 'v' } })).toBe(0);
  });

  it.each([
    ['(A)', '$.items[?((@.type == "b"))]'],
    ['(A) || (B)', '$.items[?((@.type == "b") || (@.type == "c"))]'],
  ])('既知の限界: 式全体を括弧で囲んだフィルタ %s は型違反の要素で path 全体が解決不能になる（fail-closed）', (_, path) => {
    const claims = { items: [{ type: ['a'] }, { type: 'b' }] };
    // 括弧で囲まなければ一致する要素は残る（上のケース）。囲むとスクリプト式と区別できず全体が一致なしに倒れる。
    expect(matchCount('$.items[?(@.type == "b")]', claims)).toBe(1);
    expect(matchCount(path, claims)).toBe(0);
    // 型違反の要素が無ければ、括弧で囲んでも通常どおり一致する。
    expect(matchCount(path, { items: [{ type: 'b' }] })).toBe(1);
  });
});
