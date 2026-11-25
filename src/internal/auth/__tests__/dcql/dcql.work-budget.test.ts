/**
 * DCQL 評価の仕事量予算の回帰テスト（最小単位の計上）。
 *
 * 要件 × VC の組・`path` のキー・`values` / `vct_values` の要素が、評価関数の入口で共有予算
 * （`MAX_DCQL_WORK_UNITS`）を消費することを、実時間ではなく決定的な予算の残量と例外で pin する。
 * 形状を変えて（少数の巨大要素 / 多数の極小要素）同じ予算が効くことを確かめる。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../__tests__/heavy-input-timeout.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  createDcqlWorkBudget,
  DCQL_WORK_EXCEEDED_REASON,
  MAX_DCQL_WORK_UNITS,
} from '../../dcql/budget.js';
import {
  type DcqlQuery,
  evaluateDcql,
  findMatchingCredentialIndexes,
  type QueryableCredential,
} from '../../dcql/dcql.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

function credential(id: string, claims: Record<string, unknown> = { a: 1 }): QueryableCredential {
  return { id, format: 'dc+sd-jwt', vct: 'v', claims };
}

function expectBudgetError(fn: () => unknown): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    expect((error as VericertsError).context).toEqual({ reason: DCQL_WORK_EXCEEDED_REASON });
    return;
  }
  throw new Error('expected the DCQL work budget to be exceeded');
}

describe('DCQL 評価の計上単位', () => {
  it('要件 1 件 × VC 1 件は format 不一致でも固定費 1 を計上する', () => {
    const budget = createDcqlWorkBudget();
    const query: DcqlQuery = { credentials: [{ id: 'q', format: 'jwt_vc_json' }] };
    findMatchingCredentialIndexes(query, [credential('a'), credential('b')], budget);
    expect(MAX_DCQL_WORK_UNITS - budget.remaining).toBe(2);
  });

  it('claim 1 件の path 解決（1 + キー数）と values の要素数を計上する', () => {
    const budget = createDcqlWorkBudget();
    const query: DcqlQuery = {
      credentials: [
        {
          id: 'q',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['v', 'w', 'x'] },
          claims: [{ path: ['a'], values: [1, 2, 3, 4] }],
        },
      ],
    };
    const result = findMatchingCredentialIndexes(query, [credential('a')], budget);
    expect(result).toEqual([0]);
    // 組 1 + vct_values 3 + path (1 + 1) + values 4
    expect(MAX_DCQL_WORK_UNITS - budget.remaining).toBe(1 + 3 + 2 + 4);
  });

  it('evaluateDcql も同じ予算に計上する（予算を渡して共有できる）', () => {
    const budget = createDcqlWorkBudget();
    const query: DcqlQuery = { credentials: [{ id: 'q', format: 'dc+sd-jwt' }] };
    evaluateDcql(query, [credential('a'), credential('b'), credential('c')], budget);
    expect(MAX_DCQL_WORK_UNITS - budget.remaining).toBe(3);
  });
});

describe('DCQL 評価は総量の予算で 8030 に倒れる', () => {
  // 形状 1: 少数の巨大要素（claim の values が上限件数）× 多数の VC。
  it('values 128 件の claim × 保有 VC が予算を超えると 8030', () => {
    const values = Array.from({ length: 128 }, (_, i) => i + 1000);
    const query: DcqlQuery = {
      credentials: [{ id: 'q', format: 'dc+sd-jwt', claims: [{ path: ['a'], values }] }],
    };
    // 1 VC あたり 1 + 2 + 128 = 131 単位。
    const holdings = Math.ceil(MAX_DCQL_WORK_UNITS / 131) + 1;
    const vcs = Array.from({ length: holdings }, (_, i) => credential(`v${i}`));
    expectBudgetError(() => findMatchingCredentialIndexes(query, vcs));
    expectBudgetError(() => evaluateDcql(query, vcs));
  });

  // 形状 2: 多数の極小要素（format 不一致で即終了する要件）× 多数の VC。
  it('要件 64 件 × format 不一致の VC が予算を超えると 8030（固定費だけで頭打ち）', () => {
    const query: DcqlQuery = {
      credentials: Array.from({ length: 64 }, (_, i) => ({ id: `q${i}`, format: 'jwt_vc_json' })),
    };
    const holdings = Math.ceil(MAX_DCQL_WORK_UNITS / 64) + 1;
    const vcs = Array.from({ length: holdings }, (_, i) => credential(`v${i}`));
    expectBudgetError(() => findMatchingCredentialIndexes(query, vcs));
  });

  // 形状 3: 深い path（上限長）の claim を多数。
  it('path 16 キー × claim 128 件 × 保有 VC が予算を超えると 8030', () => {
    const path = Array.from({ length: 16 }, (_, i) => `k${i}`);
    const claims = Array.from({ length: 128 }, () => ({ path }));
    const query: DcqlQuery = { credentials: [{ id: 'q', format: 'dc+sd-jwt', claims }] };
    // どの VC も最初のキーが無く 1 claim で終わるため、1 VC あたり 1 + 17 単位。
    const holdings = Math.ceil(MAX_DCQL_WORK_UNITS / 18) + 1;
    const vcs = Array.from({ length: holdings }, (_, i) => credential(`v${i}`));
    expectBudgetError(() => findMatchingCredentialIndexes(query, vcs));
  });

  it('通常規模（要件数個 × claim 数個 × VC 数千件）は予算内で従来どおり一致する', () => {
    const query: DcqlQuery = {
      credentials: [
        {
          id: 'q',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['v'] },
          claims: [{ path: ['a'], values: [1, 2] }, { path: ['a'] }],
        },
      ],
    };
    const vcs = Array.from({ length: 5000 }, (_, i) => credential(`v${i}`));
    expect(findMatchingCredentialIndexes(query, vcs)).toHaveLength(5000);
    expect(evaluateDcql(query, vcs)).toHaveLength(5000);
  });
});
