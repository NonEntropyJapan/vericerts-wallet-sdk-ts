/**
 * `constraints` の強制の仕事量予算。
 *
 * 以前は下位 `metadata` の Entity Type（N 個）を `allowed_entity_types`（M 件）へ `includes` で総当たりし
 * O(N×M) だった。Statement 本文予算は JWT の文字数しか数えないため、予算内の 1.9 MB
 * （N=M=約 35,000）で `buildTrustChain` が 9〜14 秒停止した。実時間ではなく、`includes` の呼び出し回数・
 * 予算の消費量・例外の種別で pin する。N と M の比率を変えた複数形状（少数 × 多数・多数 × 少数・同数）で確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { enforceSubordinateConstraints } from '../../constraints/enforce.js';
import {
  createStatementBudget,
  MAX_CHAIN_CONSTRAINT_STEPS,
  type StatementBudget,
} from '../../statement/statement-budget.js';
import { buildTrustChain } from '../../trust-chain.js';
import {
  ANCHOR_KEY,
  INTERMEDIATE_KEY,
  LEAF_KEY,
  makeFetchMock,
  nowFn,
  signStatement,
  toJwk,
  validPeriod,
} from '../federation-fixtures.js';

const names = (prefix: string, count: number): string[] =>
  Array.from({ length: count }, (_, i) => `${prefix}${i}`);

/** `includes` の呼び出し回数を数える許可リスト（線形化されていれば 0 回）。 */
function countingAllowList(entries: string[]): { list: string[]; includesCalls: () => number } {
  let calls = 0;
  const list = [...entries];
  list.includes = (...args: Parameters<string[]['includes']>) => {
    calls += 1;
    return Array.prototype.includes.apply(entries, args);
  };
  return { list, includesCalls: () => calls };
}

function caughtOf(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

function expectBudgetExceeded(error: unknown): void {
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
  expect((error as VericertsError).context).toMatchObject({ reason: 'constraint_budget_exceeded' });
}

describe('enforceSubordinateConstraints: allowed_entity_types の照合は線形', () => {
  // [形状, 下位 Entity Type 数 N, 許可リスト長 M]。いずれも N + M は予算内（型は許可リストを循環して全件許可）。
  it.each([
    ['同数（20,000 × 20,000）', 20_000, 20_000],
    ['少数の Entity Type × 巨大な許可リスト', 3, 60_000],
    ['多数の Entity Type × 小さな許可リスト', 60_000, 3],
  ])('%s: includes を呼ばず、予算を N + M だけ消費する', (_shape, n, m) => {
    const { list, includesCalls } = countingAllowList(names('t', m));
    const entityTypes = Array.from({ length: n }, (_, i) => `t${i % m}`);
    const budget = createStatementBudget();
    enforceSubordinateConstraints(
      { allowed_entity_types: list },
      { entityIds: ['https://leaf.example.eu'], entityTypes },
      budget,
    );
    expect(includesCalls()).toBe(0);
    expect(budget.remainingConstraintSteps).toBe(MAX_CHAIN_CONSTRAINT_STEPS - (n + m));
  });

  it('許可リストに無い型があれば拒否（Set 化しても意味は変わらない）', () => {
    const error = caughtOf(() =>
      enforceSubordinateConstraints(
        { allowed_entity_types: names('t', 1000) },
        { entityIds: ['https://leaf.example.eu'], entityTypes: ['t999', 'other'] },
        createStatementBudget(),
      ),
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.TRUST_CHAIN_INVALID);
    expect((error as VericertsError).context).toBeUndefined();
  });

  it('federation_entity は許可リストに無くても常に許可', () => {
    expect(() =>
      enforceSubordinateConstraints(
        { allowed_entity_types: ['openid_provider'] },
        { entityIds: ['https://leaf.example.eu'], entityTypes: ['federation_entity'] },
        createStatementBudget(),
      ),
    ).not.toThrow();
  });
});

describe('enforceSubordinateConstraints: 走査・照合数の予算', () => {
  it.each([
    ['巨大な許可リスト × 少数の型', 70_000, 2],
    ['少数の許可リスト × 巨大な型の列', 2, 70_000],
    ['同数', 33_000, 33_000],
  ])('%s: 予算超過は何も照合せず拒否し、予算も消費しない', (_shape, m, n) => {
    const budget = createStatementBudget();
    const before = budget.remainingConstraintSteps;
    const error = caughtOf(() =>
      enforceSubordinateConstraints(
        { allowed_entity_types: names('a', m) },
        { entityIds: ['https://leaf.example.eu'], entityTypes: names('t', n) },
        budget,
      ),
    );
    expectBudgetExceeded(error);
    expect(budget.remainingConstraintSteps).toBe(before);
  });

  it('名前制約の照合数（下位の ID 数 × 名前数）も計上して超過を拒否する', () => {
    const entityIds = Array.from({ length: 9 }, (_, i) => `https://e${i}.example.eu`);
    const permitted = names('.p', 8_000).map((n) => `${n}.example.eu`);
    const budget = createStatementBudget();
    expectBudgetExceeded(
      caughtOf(() =>
        enforceSubordinateConstraints(
          { naming_constraints: { permitted } },
          { entityIds, entityTypes: [] },
          budget,
        ),
      ),
    );
  });

  it('名前制約の消費量は ID 数 × (permitted + excluded) で、予算内なら通る', () => {
    const entityIds = ['https://a.example.eu', 'https://b.example.eu'];
    const budget = createStatementBudget();
    enforceSubordinateConstraints(
      {
        naming_constraints: {
          permitted: ['.example.eu'],
          excluded: ['x.example.com', 'y.example.com'],
        },
      },
      { entityIds, entityTypes: [] },
      budget,
    );
    expect(budget.remainingConstraintSteps).toBe(MAX_CHAIN_CONSTRAINT_STEPS - 2 * 3);
  });

  it('予算は連鎖全体で共有され、複数回の強制の合計で尽きる', () => {
    const budget: StatementBudget = createStatementBudget();
    const subjects = { entityIds: ['https://leaf.example.eu'], entityTypes: names('t', 20_000) };
    const constraints = { allowed_entity_types: names('t', 20_000) };
    enforceSubordinateConstraints(constraints, subjects, budget);
    expect(budget.remainingConstraintSteps).toBe(MAX_CHAIN_CONSTRAINT_STEPS - 40_000);
    // 2 回目は 40,000 > 残り 25,536 で拒否される。
    expectBudgetExceeded(
      caughtOf(() => enforceSubordinateConstraints(constraints, subjects, budget)),
    );
    expect(budget.remainingConstraintSteps).toBe(MAX_CHAIN_CONSTRAINT_STEPS - 40_000);
  });
});

const LEAF = 'https://leaf.example.eu';
const INT = 'https://intermediate.example.eu';
const ANCHOR = 'https://anchor.example.eu';

/**
 * Leaf の Entity Configuration に `metadataKeys` 個の Entity Type を載せ、Intermediate が Leaf について
 * `allowed_entity_types`（`allowedTypes` 件）の制約を課す 3 段チェーンを組む。
 */
async function buildWithEntityTypes(metadataKeys: number, allowedTypes: number) {
  const leafJwks = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };
  const intJwks = { keys: [toJwk(INTERMEDIATE_KEY, 'int-1')] };
  const anchorJwks = { keys: [toJwk(ANCHOR_KEY, 'anchor-1')] };
  const endpoint = (id: string) => ({
    metadata: { federation_entity: { federation_fetch_endpoint: `${id}/fetch` } },
  });
  const leafMetadata = Object.fromEntries(names('t', metadataKeys).map((key) => [key, {}]));
  const ec = (key: Uint8Array, id: string, jwks: unknown, rest: Record<string, unknown>) =>
    signStatement(key, { iss: id, sub: id, ...validPeriod(), jwks, ...rest });
  const responses = new Map<string, string>([
    [
      `${LEAF}/.well-known/openid-federation`,
      ec(LEAF_KEY, LEAF, leafJwks, { authority_hints: [INT], metadata: leafMetadata }),
    ],
    [
      `${INT}/.well-known/openid-federation`,
      ec(INTERMEDIATE_KEY, INT, intJwks, { authority_hints: [ANCHOR], ...endpoint(INT) }),
    ],
    [
      `${ANCHOR}/.well-known/openid-federation`,
      ec(ANCHOR_KEY, ANCHOR, anchorJwks, endpoint(ANCHOR)),
    ],
    [
      `${INT}/fetch?sub=${encodeURIComponent(LEAF)}`,
      signStatement(INTERMEDIATE_KEY, {
        iss: INT,
        sub: LEAF,
        ...validPeriod(),
        jwks: leafJwks,
        constraints: { allowed_entity_types: names('t', allowedTypes) },
      }),
    ],
    [
      `${ANCHOR}/fetch?sub=${encodeURIComponent(INT)}`,
      signStatement(ANCHOR_KEY, { iss: ANCHOR, sub: INT, ...validPeriod(), jwks: intJwks }),
    ],
  ]);
  return buildTrustChain(LEAF, ANCHOR, { fetchFn: makeFetchMock(responses), now: nowFn });
}

describe('buildTrustChain: Entity Type × 許可リストの増幅は予算で拒否', () => {
  // どれも JWT は 1 通 1 MiB 未満・Statement 本文予算（2 MiB）の内側で、走査・照合の総数だけが予算を超える。
  it.each([
    ['多数の metadata キー × 中規模の許可', 50_000, 20_000],
    ['少数の metadata キー × 巨大な許可リスト', 5, 70_000],
    ['同数（35,000 × 35,000）', 35_000, 35_000],
  ])('%s', async (_shape, keys, allowed) => {
    let caught: unknown;
    try {
      await buildWithEntityTypes(keys, allowed);
    } catch (error) {
      caught = error;
    }
    expectBudgetExceeded(caught);
  });

  it('予算内（20,000 × 20,000）の全許可は成立する', async () => {
    const chain = await buildWithEntityTypes(20_000, 20_000);
    expect(chain.valid).toBe(true);
  });
});
