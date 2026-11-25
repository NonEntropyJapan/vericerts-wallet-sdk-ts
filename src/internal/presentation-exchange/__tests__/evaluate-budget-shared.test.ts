/**
 * PEx の共有予算の取りこぼしの回帰テスト。
 *
 * 実時間ではなく決定的なカウンタ（コンパイル回数・予算の残量・`JSONPath.cache` の件数・budgetedView の計上量）で pin する。
 *
 * - `jsonpath-plus` の静的キャッシュ `JSONPath.cache` がリクエストをまたいで無制限に増えない。
 * - `minLength` / `maxLength` の全走査を `scan` 予算へ計上し、境界が O(1) で決まるときは走査しない。
 * - `filter.pattern` は予算 1 つ（Presentation Request 1 件）の中で同じ文字列を 1 回だけコンパイルする。
 * - `path` の読み出しは対象の深さも計上し、深く細長いクレームの O(N×D) 確保を予算で止める。
 */

import { describe, expect, it } from 'bun:test';
import { JSONPath } from 'jsonpath-plus';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { MAX_SCAN_UNITS, stringScanUnits } from '../../credential/json-schema/internals.js';
import { createPexBudget } from '../budget.js';
import { parsePresentationDefinition } from '../definition.js';
import { evaluatePresentationDefinitionWithBudget } from '../evaluate.js';
import { MAX_JSONPATH_CACHE_ENTRIES } from '../jsonpath-cache.js';
import { budgetedView, MAX_PATH_READS, type PathBudget } from '../path-budget.js';

function credentialWith(claims: Record<string, unknown>, id = 'vc'): QueryableCredential {
  return { id, format: 'dc+sd-jwt', claims };
}

/** 同じ 1 field を `count` 個持つ記述子 1 件の PD。 */
function repeatedFieldDefinition(field: Record<string, unknown>, count: number) {
  return parsePresentationDefinition({
    id: 'pd',
    input_descriptors: [
      { id: 'd', constraints: { fields: Array.from({ length: count }, () => field) } },
    ],
  });
}

describe('filter.pattern のコンパイルは予算 1 つの中でソースごとに 1 回', () => {
  const PATTERN = '[a-zA-Z0-9_]{0,300}[^abc]{0,300}(x|y|z){0,100}';
  const field = { path: ['$.s'], filter: { type: 'string', pattern: PATTERN } };

  it('同一 pattern の 16 field × 保有 VC 25 件でもコンパイルは 1 回で、結果は全 VC で一致する', () => {
    const budget = createPexBudget();
    const pd = repeatedFieldDefinition(field, 16);
    let matched = 0;
    for (let i = 0; i < 25; i += 1) {
      matched += evaluatePresentationDefinitionWithBudget(
        pd,
        [credentialWith({ s: 'a' }, `vc-${i}`)],
        budget,
      ).length;
    }
    expect(matched).toBe(25);
    expect(budget.patternCompiles).toBe(1);
  });

  it('異なる pattern はそれぞれ 1 回ずつコンパイルし、コンパイル費用（pattern 長）をステップ予算から差し引く', () => {
    const budget = createPexBudget();
    const before = budget.regex.remaining;
    const patterns = ['^a$', '^[a-z]+$', '^a|b$'];
    const pd = parsePresentationDefinition({
      id: 'pd',
      input_descriptors: patterns.map((pattern, i) => ({
        id: `d${i}`,
        constraints: { fields: [{ path: ['$.s'], filter: { type: 'string', pattern } }] },
      })),
    });
    evaluatePresentationDefinitionWithBudget(pd, [credentialWith({ s: 'a' })], budget);
    evaluatePresentationDefinitionWithBudget(pd, [credentialWith({ s: 'b' })], budget);
    expect(budget.patternCompiles).toBe(patterns.length);
    const compileCost = patterns.reduce((sum, p) => sum + p.length, 0);
    expect(before - budget.regex.remaining).toBeGreaterThanOrEqual(compileCost);
  });

  it('構文不正の pattern も失敗をメモし、再コンパイルせず不一致を返す', () => {
    const budget = createPexBudget();
    const pd = repeatedFieldDefinition(
      { path: ['$.s'], filter: { type: 'string', pattern: '(' } },
      8,
    );
    for (let i = 0; i < 5; i += 1) {
      expect(
        evaluatePresentationDefinitionWithBudget(pd, [credentialWith({ s: 'a' })], budget),
      ).toEqual([]);
    }
    expect(budget.patternCompiles).toBe(1);
  });

  it('ステップ予算が pattern 長に足りないときはコンパイルせずに不一致（fail-closed）', () => {
    const budget = createPexBudget();
    budget.regex.remaining = PATTERN.length - 1;
    const matches = evaluatePresentationDefinitionWithBudget(
      repeatedFieldDefinition(field, 4),
      [credentialWith({ s: 'a' })],
      budget,
    );
    expect(matches).toEqual([]);
    expect(budget.patternCompiles).toBe(0);
  });
});

describe('minLength / maxLength の走査量は scan 予算へ計上する', () => {
  const LENGTH = 100_000;
  const claims = { note: 'a'.repeat(LENGTH) };
  /** 全文字がサロゲートペア（UTF-16 長 LENGTH・コードポイント数 LENGTH / 2）の文字列。 */
  const pairs = { note: '😀'.repeat(LENGTH / 2) };
  const run = (
    filter: Record<string, unknown>,
    count: number,
    scanRemaining?: number,
    held: Record<string, unknown> = claims,
  ) => {
    const budget = createPexBudget();
    if (scanRemaining !== undefined) {
      budget.scan.scanRemaining = scanRemaining;
    }
    const matches = evaluatePresentationDefinitionWithBudget(
      repeatedFieldDefinition({ path: ['$.note'], filter: { type: 'string', ...filter } }, count),
      [credentialWith(held)],
      budget,
    );
    return { matches, budget };
  };

  it('UTF-16 長だけで境界が決まる filter は走査せず、scan 予算を消費しない', () => {
    const { matches, budget } = run({ minLength: 1, maxLength: 10_000_000 }, 64);
    expect(matches).toHaveLength(1);
    expect(budget.scan.scanRemaining).toBe(MAX_SCAN_UNITS);
    // 長さの下界（半分）が maxLength を超える・上界が minLength に届かないのも走査せずに不一致。
    expect(run({ maxLength: LENGTH / 2 - 1 }, 4).matches).toEqual([]);
    expect(run({ minLength: LENGTH + 1 }, 4).matches).toEqual([]);
    expect(run({ maxLength: LENGTH / 2 - 1 }, 4).budget.scan.scanRemaining).toBe(MAX_SCAN_UNITS);
  });

  it('境界が曖昧なときだけ全走査し、その量を前払いする。使い切ったら不一致（fail-closed）', () => {
    const cost = stringScanUnits(LENGTH);
    // maxLength = 75,000: コードポイント数は UTF-16 長の半分〜全部（5 万〜10 万）の幅の中で決まらないため走査する。
    const ambiguous = { maxLength: 75_000 };
    const one = run(ambiguous, 1, undefined, pairs);
    expect(one.matches).toHaveLength(1);
    expect(MAX_SCAN_UNITS - one.budget.scan.scanRemaining).toBe(cost);

    // 予算が 3 回分しかなければ、4,096 個並べても走査は 3 回で打ち切られる。
    const starved = run(ambiguous, 64, cost * 3, pairs);
    expect(starved.matches).toEqual([]);
    expect(starved.budget.scan.exhausted).toBe(true);
    expect(starved.budget.scan.scanRemaining).toBe(0);
  });

  it('コードポイント単位で数える（サロゲートペアは 1 文字）', () => {
    const emoji = { note: '😀'.repeat(5) };
    const matchCount = (filter: Record<string, unknown>) =>
      evaluatePresentationDefinitionWithBudget(
        repeatedFieldDefinition({ path: ['$.note'], filter: { type: 'string', ...filter } }, 1),
        [credentialWith(emoji)],
        createPexBudget(),
      ).length;
    expect(matchCount({ maxLength: 5 })).toBe(1);
    expect(matchCount({ maxLength: 4 })).toBe(0);
    expect(matchCount({ minLength: 5 })).toBe(1);
    expect(matchCount({ minLength: 6 })).toBe(0);
  });
});

describe('path の読み出しは対象の深さも計上する', () => {
  it('budgetedView は深さ D のノードの読み出し 1 回を 1 + D 単位で計上する', () => {
    const budget: PathBudget = { remaining: 1_000, exhausted: false };
    const view = budgetedView({ a: { b: { c: 1 } } }, budget) as { a: { b: { c: number } } };
    expect(view.a.b.c).toBe(1);
    // a（深さ 0: 1）+ b（深さ 1: 2）+ c（深さ 2: 3）。
    expect(1_000 - budget.remaining).toBe(1 + 2 + 3);
  });

  it('深さ 500・葉 5,000 の細長いクレームは `$..*` が予算超過で不一致（読み出し回数だけでは予算内の規模）', () => {
    const DEPTH = 500;
    const LEAVES = 5_000;
    let node: unknown = Array.from({ length: LEAVES }, () => 0);
    for (let i = 0; i < DEPTH; i += 1) {
      node = { a: node };
    }
    const budget = createPexBudget();
    const matches = evaluatePresentationDefinitionWithBudget(
      parsePresentationDefinition({
        id: 'pd',
        input_descriptors: [
          { id: 'd', constraints: { fields: [{ path: ['$..*'], optional: true }] } },
        ],
      }),
      [credentialWith({ deep: node as Record<string, unknown> })],
      budget,
    );
    expect(matches).toEqual([]);
    expect(budget.paths.exhausted).toBe(true);
    // 読み出し回数（≈ LEAVES + DEPTH）だけなら MAX_PATH_READS の数 % だが、深さ加算で予算を超える。
    expect(LEAVES + DEPTH).toBeLessThan(MAX_PATH_READS / 100);
  });

  it('通常規模（深さ 4・数十ノード）のクレームは `$..*` を従来どおり解決する', () => {
    const budget = createPexBudget();
    const matches = evaluatePresentationDefinitionWithBudget(
      parsePresentationDefinition({
        id: 'pd',
        input_descriptors: [{ id: 'd', constraints: { fields: [{ path: ['$..name'] }] } }],
      }),
      [
        credentialWith({
          credentialSubject: { address: { street: { name: 'x' } }, items: [1, 2, 3] },
        }),
      ],
      budget,
    );
    expect(matches).toHaveLength(1);
    expect(budget.paths.exhausted).toBe(false);
  });
});

describe('JSONPath.cache は件数が上限で頭打ちになる', () => {
  const cacheKeys = () => Object.keys((JSONPath as unknown as { cache: object }).cache);

  it('相異なる path（式つき・式なし）を上限の数倍評価しても、保持件数は MAX_JSONPATH_CACHE_ENTRIES 以下', () => {
    const claims = { a: [{ x: 1 }, { x: 2 }], k: 'v' };
    const total = MAX_JSONPATH_CACHE_ENTRIES * 4;
    for (let i = 0; i < total; i += 1) {
      const path = i % 2 === 0 ? `$.a[?(@.x==${i})]` : `$.k${i}`;
      evaluatePresentationDefinitionWithBudget(
        repeatedFieldDefinition({ path: [path], optional: true }, 1),
        [credentialWith(claims)],
        createPexBudget(),
      );
      expect(cacheKeys().length).toBeLessThanOrEqual(MAX_JSONPATH_CACHE_ENTRIES);
    }
  });

  it('キャッシュを全消去しても評価結果は変わらない（再計算するだけ）', () => {
    const pd = repeatedFieldDefinition({ path: ['$.a[?(@.x==2)]'] }, 1);
    const claims = { a: [{ x: 1 }, { x: 2 }] };
    for (let i = 0; i < MAX_JSONPATH_CACHE_ENTRIES * 2; i += 1) {
      expect(
        evaluatePresentationDefinitionWithBudget(pd, [credentialWith(claims)], createPexBudget()),
      ).toHaveLength(1);
      evaluatePresentationDefinitionWithBudget(
        repeatedFieldDefinition({ path: [`$.z${i}`], optional: true }, 1),
        [credentialWith(claims)],
        createPexBudget(),
      );
    }
  });

  it('`__proto__` / `constructor` のような path でも Object.prototype をキャッシュ済みと誤読しない', () => {
    for (const path of ['$.__proto__', '$.constructor', '$.toString']) {
      const matches = evaluatePresentationDefinitionWithBudget(
        repeatedFieldDefinition({ path: [path] }, 1),
        [credentialWith({ k: 'v' })],
        createPexBudget(),
      );
      expect(matches).toEqual([]);
    }
  });
});
