/**
 * PEx の評価単位ごとの計上の回帰テスト。
 *
 * 「1 フィールド / 1 path / 1 enum 要素」の評価が必ず共有予算を消費することを、実時間ではなく決定的な
 * カウンタ（予算の残量・要素の読み出し回数・`claims` への到達回数）で pin する。形状を変えて
 * （少数の巨大要素 / 多数の極小要素）同じ予算が効くことを確かめる。
 *
 * - 読み出しの無い path（`$` / `$^` / `$~`）・`optional` で解決できない field・filter の無い field も
 *   呼び出し固定費を `paths` 予算へ計上する。
 * - `filter.enum` は件数上限があり、`scan` 予算が尽きたら残りの要素を比較しない。
 *   予算が尽きた後は記述子 × VC のループも打ち切る。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../__tests__/heavy-input-timeout.js';
import type { QueryableCredential } from '../../auth/dcql/dcql.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { createPexBudget } from '../budget.js';
import { parsePresentationDefinition } from '../definition.js';
import { evaluatePresentationDefinitionWithBudget } from '../evaluate.js';
import { matchesFilter } from '../filter.js';
import { parseFilter } from '../filter-definition.js';
import { MAX_FILTER_ENUM_LENGTH } from '../limits.js';
import { FIELD_EVALUATION_COST, MAX_PATH_READS, PATH_CALL_COST } from '../path-budget.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

function credentialWith(claims: Record<string, unknown>, id = 'vc'): QueryableCredential {
  return { id, format: 'dc+sd-jwt', claims };
}

/** `descriptors` 件の記述子が、それぞれ同じ `fields` を持つ PD。 */
function definitionOf(descriptors: number, fields: readonly Record<string, unknown>[]) {
  return parsePresentationDefinition({
    id: 'pd',
    input_descriptors: Array.from({ length: descriptors }, (_, i) => ({
      id: `d${i}`,
      constraints: { fields },
    })),
  });
}

/** `claims` への到達（プロパティ読み出し・列挙）回数を数える VC。 */
function countingCredential(id = 'vc') {
  const state = { touches: 0 };
  const claims = new Proxy(
    { name: 'x' },
    {
      get(target, key, receiver) {
        state.touches++;
        return Reflect.get(target, key, receiver);
      },
      ownKeys(target) {
        state.touches++;
        return Reflect.ownKeys(target);
      },
      has(target, key) {
        state.touches++;
        return Reflect.has(target, key);
      },
    },
  );
  return { credential: credentialWith(claims, id), state };
}

describe('読み出しの無い path も呼び出し固定費を計上する', () => {
  for (const path of ['$', '$^', '$~']) {
    it(`path ${path} の optional field を N 回評価すると、予算が N × (field + path 固定費) だけ減る`, () => {
      const budget = createPexBudget();
      const count = 64;
      const pd = definitionOf(
        1,
        Array.from({ length: count }, () => ({ path: [path], optional: true })),
      );
      evaluatePresentationDefinitionWithBudget(pd, [credentialWith({ name: 'x' })], budget);
      const perField = FIELD_EVALUATION_COST + PATH_CALL_COST;
      // 記述子 × VC の組の固定費 1 を加える。
      expect(MAX_PATH_READS - budget.paths.remaining).toBeGreaterThanOrEqual(count * perField + 1);
      expect(budget.paths.exhausted).toBe(false);
    });
  }

  it('path が解決できない optional field も、filter の無い field も、1 件ごとに固定費を計上する', () => {
    const budget = createPexBudget();
    const fields = [
      { path: ['$.missing'], optional: true },
      { path: ['$.name'] },
      { path: ['$.a', '$.b', '$.c'], optional: true },
    ];
    evaluatePresentationDefinitionWithBudget(
      definitionOf(1, fields),
      [credentialWith({ name: 'x' })],
      budget,
    );
    const consumed = MAX_PATH_READS - budget.paths.remaining;
    // field 3 件 + JSONPath 呼び出し（1 + 1 + 3 件）。読み出し分は含まない下限。
    expect(consumed).toBeGreaterThanOrEqual(3 * FIELD_EVALUATION_COST + 5 * PATH_CALL_COST);
  });

  // 形状: 多数の極小記述子 × 多数の VC（field 1 件 = 読み出し無しの path）。総回数は予算で頭打ちになる。
  it('多数の記述子 × 多数の VC で予算が尽き、以降の VC には JSONPath を一度も呼ばない', () => {
    const budget = createPexBudget();
    const pd = definitionOf(64, [{ path: ['$^'], optional: true }]);
    const perPair = 1 + FIELD_EVALUATION_COST + PATH_CALL_COST;
    const pairsToExhaust = Math.ceil(MAX_PATH_READS / perPair);
    const holdings = Math.ceil(pairsToExhaust / 64) + 5;
    const credentials = Array.from({ length: holdings }, () => credentialWith({ name: 'x' }));
    const matches = evaluatePresentationDefinitionWithBudget(pd, credentials, budget);
    expect(budget.paths.exhausted).toBe(true);
    expect(budget.paths.remaining).toBe(0);
    // 尽きるまでに評価できた組は、予算から決まる上限を超えない。
    expect(matches.length).toBeLessThanOrEqual(pairsToExhaust);
    // 予算が尽きた後は同じ予算での評価が claims に一度も触れない。
    const probe = countingCredential();
    const after = evaluatePresentationDefinitionWithBudget(pd, [probe.credential], budget);
    expect(after).toEqual([]);
    expect(probe.state.touches).toBe(0);
  });

  // 形状: 少数の巨大要素（1 記述子 × 最大 field 数 × 少数 VC）でも同じ予算が効く。
  it('1 記述子 × 64 field × 多数の VC でも総計が予算で頭打ちになる', () => {
    const budget = createPexBudget();
    const fields = Array.from({ length: 64 }, () => ({ path: ['$~'], optional: true }));
    const pd = definitionOf(1, fields);
    const perVc = 1 + 64 * (FIELD_EVALUATION_COST + PATH_CALL_COST);
    const holdings = Math.ceil(MAX_PATH_READS / perVc) + 10;
    const credentials = Array.from({ length: holdings }, () => credentialWith({ name: 'x' }));
    const matches = evaluatePresentationDefinitionWithBudget(pd, credentials, budget);
    expect(budget.paths.exhausted).toBe(true);
    expect(matches.length).toBeLessThan(holdings);
  });

  it('通常規模の PD（数 field × 数 VC）は予算を使い切らず従来どおり一致する', () => {
    const budget = createPexBudget();
    const pd = definitionOf(3, [
      { path: ['$.name'], filter: { type: 'string', enum: ['x', 'y'] } },
      { path: ['$.missing'], optional: true },
    ]);
    const credentials = Array.from({ length: 50 }, (_, i) =>
      credentialWith({ name: 'x' }, `v${i}`),
    );
    const matches = evaluatePresentationDefinitionWithBudget(pd, credentials, budget);
    expect(matches).toHaveLength(150);
    expect(budget.paths.exhausted).toBe(false);
    expect(budget.scan.exhausted).toBe(false);
  });
});

/** 要素の読み出し（添字アクセス）回数を数える `enum` 配列。 */
function countingEnum(values: readonly unknown[]) {
  const state = { indexReads: 0 };
  const proxy = new Proxy([...values], {
    get(target, key, receiver) {
      if (typeof key === 'string' && /^\d+$/.test(key)) {
        state.indexReads++;
      }
      return Reflect.get(target, key, receiver);
    },
  });
  return { proxy, state };
}

describe('filter.enum の件数上限と走査の打ち切り', () => {
  it('パース時に 1,024 件までは受理し、超えると 8030 (filter_enum_too_large)', () => {
    expect(MAX_FILTER_ENUM_LENGTH).toBe(1_024);
    expect(
      parseFilter({ type: 'number', enum: Array(MAX_FILTER_ENUM_LENGTH).fill(0) }).enum,
    ).toHaveLength(MAX_FILTER_ENUM_LENGTH);
    try {
      parseFilter({ type: 'number', enum: Array(MAX_FILTER_ENUM_LENGTH + 1).fill(0) });
      throw new Error('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
      expect((error as VericertsError).context).toEqual({ reason: 'filter_enum_too_large' });
    }
  });

  it('scan 予算が既に尽きていれば、enum の要素を 1 件も読まずに不一致', () => {
    const budget = createPexBudget();
    budget.scan.scanRemaining = 0;
    budget.scan.exhausted = true;
    const { proxy, state } = countingEnum(Array(MAX_FILTER_ENUM_LENGTH).fill(1));
    expect(matchesFilter(5, { type: 'number', enum: proxy }, budget)).toBe(false);
    expect(state.indexReads).toBe(0);
  });

  // 形状: 多数の極小要素。予算が数単位しか無ければ、数件の比較で止まる。
  it('多数の極小要素: 予算が尽きた時点で残りの要素を比較しない', () => {
    const budget = createPexBudget();
    budget.scan.scanRemaining = 3;
    const { proxy, state } = countingEnum(Array(MAX_FILTER_ENUM_LENGTH).fill(1));
    expect(matchesFilter(5, { type: 'number', enum: proxy }, budget)).toBe(false);
    expect(budget.scan.exhausted).toBe(true);
    // 3 単位 = 3 件の比較で尽き、4 件目の比較（尽きる判定）で止まる。
    expect(state.indexReads).toBeLessThanOrEqual(4);
  });

  // 形状: 少数の巨大要素。巨大な文字列は 1 件の比較で予算を使い切り、残りは比較しない。
  it('少数の巨大要素: 1 件の比較で予算を使い切り、残りの要素は比較しない', () => {
    const budget = createPexBudget();
    budget.scan.scanRemaining = 1_000;
    const { proxy, state } = countingEnum(['z'.repeat(10_000_000), ...Array(100).fill('y')]);
    expect(matchesFilter('z'.repeat(10_000_000), { type: 'string', enum: proxy }, budget)).toBe(
      false,
    );
    expect(budget.scan.exhausted).toBe(true);
    expect(state.indexReads).toBeLessThanOrEqual(2);
  });

  it('enum の一致は予算内で従来どおり判定される（先頭・末尾・不一致）', () => {
    const filter = { type: 'string', enum: ['a', 'b', 'c'] };
    expect(matchesFilter('a', filter, createPexBudget())).toBe(true);
    expect(matchesFilter('c', filter, createPexBudget())).toBe(true);
    expect(matchesFilter('d', filter, createPexBudget())).toBe(false);
  });

  // 記述子 × VC のループ: scan 予算が尽きたら、以降の VC の claims に触れない。
  it('scan 予算が尽きた後は、残りの記述子 × VC を評価しない', () => {
    const budget = createPexBudget();
    budget.scan.scanRemaining = 5;
    const pd = definitionOf(4, [
      { path: ['$.name'], filter: { type: 'string', enum: ['p', 'q', 'r', 's', 't', 'u'] } },
    ]);
    const probes = Array.from({ length: 10 }, (_, i) => countingCredential(`v${i}`));
    const matches = evaluatePresentationDefinitionWithBudget(
      pd,
      probes.map((p) => p.credential),
      budget,
    );
    expect(matches).toEqual([]);
    expect(budget.scan.exhausted).toBe(true);
    const touched = probes.filter((p) => p.state.touches > 0).length;
    expect(touched).toBe(1);
  });
});
