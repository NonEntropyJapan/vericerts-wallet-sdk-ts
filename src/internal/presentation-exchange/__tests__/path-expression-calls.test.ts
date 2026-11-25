/**
 * JSONPath のフィルタ式内メソッド呼び出しの拒否（予算の迂回）。
 *
 * `jsonpath-plus` の `eval: 'safe'` は式内の `@.padStart(5e8,'x')` / `@.split('')` を実行でき、予算（読み出し回数 ×
 * 式の長さ）では引数に比例する演算コストを数えられない。式の構文木を許可リストで検査し、呼び出しを含む式は
 * 評価しない。実時間ではなく、プロトタイプのメソッドが**呼ばれた回数**（決定的カウンタ）で pin する。
 */

import { afterEach, describe, expect, it, spyOn } from 'bun:test';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { createPexBudget } from '../budget.js';
import { parsePresentationDefinition } from '../definition.js';
import { evaluatePresentationDefinitionWithBudget } from '../evaluate.js';

const CLAIMS = {
  given_name: 'Alice',
  age: 30,
  tags: ['a', 'b'],
  credentialSubject: {
    items: [
      { t: 'a', v: 1 },
      { t: 'b', v: 2 },
    ],
  },
};

const CREDENTIAL: QueryableCredential = { id: 'vc', format: 'dc+sd-jwt', claims: CLAIMS };

function matchCount(path: string, claims: Record<string, unknown> = CLAIMS): number {
  const pd = parsePresentationDefinition({
    id: 'pd',
    input_descriptors: [{ id: 'd0', constraints: { fields: [{ path: [path] }] } }],
  });
  return evaluatePresentationDefinitionWithBudget(
    pd,
    [{ ...CREDENTIAL, claims }],
    createPexBudget(),
  ).length;
}

const spies: Array<{ mockRestore(): void }> = [];

afterEach(() => {
  for (const spy of spies.splice(0)) spy.mockRestore();
});

describe('フィルタ式内のメソッド呼び出しは評価しない', () => {
  const CALL_PATHS: readonly string[] = [
    "$[?(@.padStart && @.padStart(500000000,'x').indexOf('z')>0)]",
    "$[?(@.padStart && @.padStart(500000000,'x').split('').length>0)]",
    '$[?(@.repeat && @.repeat(500000000).length>0)]',
    '$.tags[?(@.padStart && @.padStart(500000000).length>0)]',
    "$[?(@['padStart'] && @['padStart'](500000000,'x'))]",
    "$[(@.padStart(500000000,'x'))]",
  ];

  for (const path of CALL_PATHS) {
    it(`${path} は String#padStart / repeat を 1 回も呼ばず、解決できない（不一致）`, () => {
      const padStart = spyOn(String.prototype, 'padStart');
      const repeat = spyOn(String.prototype, 'repeat');
      spies.push(padStart, repeat);
      expect(matchCount(path)).toBe(0);
      expect(padStart).toHaveBeenCalledTimes(0);
      expect(repeat).toHaveBeenCalledTimes(0);
    });
  }

  it('呼び出しを含む式は、論理演算・条件式・配列リテラルの中に隠しても拒否する', () => {
    const spy = spyOn(String.prototype, 'padStart');
    spies.push(spy);
    for (const path of [
      "$[?(true || @.padStart(500000000,'x'))]",
      "$[?(@.age>0 ? @.padStart(500000000,'x') : false)]",
      "$[?([@.padStart(500000000,'x')].length)]",
      "$[?(!@.padStart(500000000,'x'))]",
    ]) {
      expect(matchCount(path)).toBe(0);
    }
    expect(spy).toHaveBeenCalledTimes(0);
  });
});

describe('通常の PEx フィルタ式は従来どおり評価できる', () => {
  it.each([
    ["$.credentialSubject.items[?(@.t=='b')].v", 1],
    ['$.credentialSubject.items[?(@.v>=1 && @.v<2)]', 1],
    ["$.credentialSubject.items[?(@.t!='z' || @.v==99)]", 1],
    ['$.credentialSubject.items[?(@.v > 0 ? true : false)]', 1],
    ['$.credentialSubject.items[?(@.v==(1+1))]', 1],
    ['$.tags[?(@.length==1)]', 1],
    ['$.credentialSubject.items[(@.length-1)]', 1],
    ['$.given_name', 1],
    ['$..t', 1],
  ])('%s', (path, expected) => {
    expect(matchCount(path)).toBe(expected);
  });
});
