/**
 * JSONPath フィルタ式の暗黙の型変換（文字列化・数値化）と、文字列オペランドの走査量の予算化。
 *
 * 以前は `+` というトークンだけを拒否したため、`[@.a,@.a,…]<'a'` のように配列リテラルを比較・単項 `+`・二項 `-` の
 * オペランドへ置くと `Array#join` による文字列化（オペランド長 × 要素数の確保）が予算なしで走った。式は
 * 自前の評価器（`guarded-eval.ts`）で評価し、オペランドがプリミティブであることを実行時に保証する。
 * 実時間・RSS ではなく、`Array.prototype.join` の呼び出し回数・一致件数・予算の残量（決定的）で pin する。
 */

import { afterEach, describe, expect, it, spyOn } from 'bun:test';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { createPexBudget } from '../budget.js';
import { parsePresentationDefinition } from '../definition.js';
import { evaluatePresentationDefinitionWithBudget } from '../evaluate.js';
import { MAX_COERCED_STRING_LENGTH } from '../guarded-eval.js';
import { MAX_PATH_READS } from '../path-budget.js';

function run(path: string, claims: Record<string, unknown>, budget = createPexBudget()) {
  const pd = parsePresentationDefinition({
    id: 'pd',
    input_descriptors: [{ id: 'd0', constraints: { fields: [{ path: [path] }] } }],
  });
  const credential: QueryableCredential = { id: 'vc', format: 'dc+sd-jwt', claims };
  return {
    matches: evaluatePresentationDefinitionWithBudget(pd, [credential], budget).length,
    budget,
  };
}

const spies: Array<{ mockRestore(): void }> = [];
afterEach(() => {
  for (const spy of spies.splice(0)) spy.mockRestore();
});

/** 1 要素の配列クレームを持つ。`a` は長い文字列。 */
const claimsOf = (a: unknown, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  s: [{ a, ...extra }],
});

describe('配列リテラル・配列 / オブジェクトのオペランドは暗黙の文字列化をさせない', () => {
  const long = `${'x'.repeat(100_000 - 1)}q`;
  const arrayOf = (n: number, term = '@.a') => `[${Array(n).fill(term).join(',')}]`;

  // 修正前はいずれも評価されて一致する（`['xx…q', …]` は `'a'` より大きい / 数値化できず比較が偽にならない形を選ぶ）。
  const shapes: [string, string][] = [
    ['配列リテラル < 文字列', `$.s[?(${arrayOf(100)}>'a')]`],
    ['配列リテラル != 数値', `$.s[?(${arrayOf(100)}!=1)]`],
    ['配列リテラル == 文字列', `$.s[?(${arrayOf(2)}=='x,y')]`],
    ['単項 + 配列リテラル', `$.s[?(+${arrayOf(100)}!=0)]`],
    ['配列リテラル - 1', `$.s[?(${arrayOf(100)}-1!=0)]`],
    ['入れ子の配列リテラル', `$.s[?([[@.a,@.a],[@.a,@.a]]>'a')]`],
    ['1 要素の入れ子', `$.s[?([[[@.a]]]>'a')]`],
    ['配列リテラルの .length（要素は読まれず許可外）', `$.s[?(${arrayOf(3)}.length==3)]`],
    ['空配列 == 0', '$.s[?([]==0)]'],
  ];

  for (const [name, path] of shapes) {
    it(`${name}: ${path.slice(0, 40)}… は Array#join を 1 回も呼ばず不一致`, () => {
      const join = spyOn(Array.prototype, 'join');
      const arrayToString = spyOn(Array.prototype, 'toString');
      spies.push(join, arrayToString);
      expect(run(path, claimsOf(long)).matches).toBe(0);
      expect(join).toHaveBeenCalledTimes(0);
      expect(arrayToString).toHaveBeenCalledTimes(0);
    });
  }

  // 配列・オブジェクトのクレーム値そのものをオペランドにしても `ToPrimitive` を起こさない。
  const operandPaths = [
    "$.s[?(@.o>'a')]",
    "$.s[?(@.o=='a,b')]",
    '$.s[?(@.o!=1)]',
    '$.s[?(-@.o==0)]',
    '$.s[?(+@.o==0)]',
    '$.s[?(~@.o==-1)]',
    '$.s[?(@.o*1==0)]',
    '$.s[?(@.o-1==-1)]',
    '$.s[?(@.o|0)]',
    '$.s[?(@.o<<1==0)]',
    "$.s[?(@.o+1=='a,b1')]",
    "$.s[?(@.p=='[object Object]')]",
    '$.s[?(@.p<1)]',
    '$.s[?(@.p==@.p)]',
    '$.s[?(@.o==@.o)]',
  ];
  for (const path of operandPaths) {
    it(`配列 / オブジェクトのオペランド ${path} は不一致で Array#join も呼ばない`, () => {
      const join = spyOn(Array.prototype, 'join');
      spies.push(join);
      expect(run(path, claimsOf('q', { o: ['a', 'b'], p: { k: 1 } })).matches).toBe(0);
      expect(join).toHaveBeenCalledTimes(0);
    });
  }

  it('関数値（`@.a.toString` 等）や constructor をオペランドにしても評価しない', () => {
    for (const path of [
      "$.s[?(@.a.toString=='x')]",
      '$.s[?(@.a.toString!=1)]',
      '$.s[?(@.a.constructor)]',
      '$.s[?(@.__proto__)]',
    ]) {
      expect(run(path, claimsOf('q')).matches).toBe(0);
    }
  });
});

describe('文字列オペランドの演算は長さを予算へ前払いするか拒否する', () => {
  const big = 1_000_000;

  it('長い文字列の数値化（@.a*1 / +@.a / @.a<1 / @.a==1）は評価せず不一致（数字だけの 1MB 文字列でも）', () => {
    const digits = '9'.repeat(big);
    for (const path of [
      '$.s[?(@.a*1>0)]',
      '$.s[?(+@.a>0)]',
      '$.s[?(-@.a<0)]',
      '$.s[?(@.a-0>0)]',
      '$.s[?(@.a>1)]',
      '$.s[?(@.a==1)]',
      '$.s[?(@.a!=1)]',
    ]) {
      expect(run(path, claimsOf(digits)).matches).toBe(0);
    }
  });

  it('短い文字列の数値化は従来どおり評価できる', () => {
    const claims = claimsOf('20');
    expect(run('$.s[?(@.a>10)]', claims).matches).toBe(1);
    expect(run('$.s[?(@.a*2==40)]', claims).matches).toBe(1);
    expect(run('$.s[?(@.a==20)]', claims).matches).toBe(1);
    const limit = 'x'.repeat(MAX_COERCED_STRING_LENGTH + 1);
    expect(run('$.s[?(@.a>10)]', claimsOf(limit)).matches).toBe(0);
  });

  it('文字列同士の比較は短い側の長さ以上を評価の前に予算へ前払いする', () => {
    const text = 'x'.repeat(big);
    const budget = createPexBudget();
    const before = budget.paths.remaining;
    // 一致する形（`<=` は同一文字列で真）。1 要素 = 1 回の比較。
    expect(run('$.s[?(@.a<=@.b)]', claimsOf(text, { b: text }), budget).matches).toBe(1);
    expect(before - budget.paths.remaining).toBeGreaterThanOrEqual(big);
  });

  for (const operator of ['<', '<=', '>', '>=', '==', '!=', '===', '!==']) {
    it(`長い文字列どうしの ${operator} を要素数ぶん繰り返すと予算が尽きて評価不能（不一致）`, () => {
      const text = 'x'.repeat(big);
      // 要素 3 つ × 1MB = 3M 単位 > MAX_PATH_READS（2M）。比較が前払いされなければ読み出し数百回で終わり一致する。
      const claims = {
        s: [
          { a: text, b: text },
          { a: text, b: text },
          { a: text, b: text },
        ],
      };
      const path = `$.s[?(@.a${operator}@.b || @.a==@.a)]`;
      const { matches, budget } = run(path, claims);
      expect(budget.paths.exhausted).toBe(true);
      expect(matches).toBe(0);
      expect(MAX_PATH_READS).toBeLessThan(3 * big);
    });
  }

  it('同じ長い文字列を `@[@.k]` の計算メンバーのキーにしても長さが前払いされる', () => {
    const key = 'k'.repeat(big);
    const claims = { s: [{ k: key }, { k: key }, { k: key }] };
    const { matches, budget } = run('$.s[?(@[@.k])]', claims);
    expect(budget.paths.exhausted).toBe(true);
    expect(matches).toBe(0);
  });

  it('+ は文字列オペランドを拒否し、数値どうし（変数を含む）は評価できる', () => {
    expect(run("$.s[?(@.a+'x'=='qx')]", claimsOf('q')).matches).toBe(0);
    expect(run('$.s[?(@.n+1==3)]', claimsOf('q', { n: 2 })).matches).toBe(1);
  });
});

describe('正当なフィルタ式は従来どおり評価できる', () => {
  const claims = {
    s: [
      {
        t: 'a',
        v: 5,
        ok: true,
        nothing: null,
        items: [{ k: 1 }, { k: 2 }],
        name: 'Alice',
      },
    ],
  };

  it.each([
    ["$.s[?(@.t=='a')]"],
    ["$.s[?(@.t!='b')]"],
    ["$.s[?(@.t==='a' && @.v>=5)]"],
    ["$.s[?(@.t!=='b' || @.v<0)]"],
    ['$.s[?(@.v>1 && @.v<10)]'],
    ['$.s[?(@.v*2==10)]'],
    ['$.s[?(@.v-1==4)]'],
    ['$.s[?(@.v%2==1)]'],
    ['$.s[?(@.v/5==1)]'],
    ['$.s[?(@.ok)]'],
    ['$.s[?(!@.missing)]'],
    ['$.s[?(@.nothing==null)]'],
    ['$.s[?(@.missing==undefined)]'],
    ['$.s[?(@.items.length==2)]'],
    ['$.s[?(@.items[0].k==1)]'],
    ["$.s[?(@.name.length==5 && @['name']=='Alice')]"],
    ["$.s[?(@.v>1 ? @.t=='a' : false)]"],
    ["$.s[?(typeof @.v=='number')]"],
    ['$.s[?(@property==0)]'],
    ['$.s[?(@root.s.length==1)]'],
    ["$.s[?(@parentProperty=='s')]"],
    ["$.s[?(@.t<'b')]"],
    ["$.s[?(@.name>='Alice')]"],
  ])('%s は一致する', (path) => {
    expect(run(path, claims).matches).toBe(1);
  });

  it('スクリプト式 `[( … )]` も評価できる', () => {
    expect(run('$.s[(@.length-1)].v', claims).matches).toBe(1);
  });
});
