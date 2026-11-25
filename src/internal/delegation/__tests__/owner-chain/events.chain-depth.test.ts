/**
 * owner 連鎖の段数上限と仕事量予算。
 *
 * 以前の `detectController` は `visited` による循環検出しか無く、攻撃者が自分で用意した N 段の owner 連鎖
 * （アドレスは無料で作れる）を指す DID を 1 つ渡すだけで、1 回の `detectController` が N 回の
 * `fetchEvents`（= `eth_getLogs` 2N 本）を逐次に発行できた。
 * 実時間ではなく、`fetchEvents` の呼び出し回数・例外種別・予算の残りで決定的に pin する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type { OwnerChangeEvent } from '../../../identity/ethr/events.js';
import {
  createResolutionWorkBudget,
  WORK_UNITS_PER_OWNER_LOOKUP,
} from '../../../identity/resolution-budget.js';
import { parseEthrDid } from '../../did-ethr.js';
import {
  detectController,
  type Erc1056EventSource,
  MAX_CONTROLLER_CHAIN_DEPTH,
} from '../../events.js';

/** `index` 番目の identity アドレス（互いに相異なる）。 */
function addressAt(index: number): string {
  return `0x${(index + 1).toString(16).padStart(40, '0')}`;
}

/** 0 → 1 → … → `hops` と owner が連なる連鎖（`hops` 段、末尾は自己所有）。`fetchEvents` の呼び出しを数える。 */
function chainOf(hops: number): { source: Erc1056EventSource; calls: string[] } {
  const calls: string[] = [];
  const source: Erc1056EventSource = {
    async fetchEvents(_chainId, address) {
      calls.push(address);
      const index = Number.parseInt(address.slice(2), 16) - 1;
      const ownerChanges: OwnerChangeEvent[] =
        index < hops ? [{ owner: addressAt(index + 1), blockNumber: 1, logIndex: 0 }] : [];
      return { ownerChanges, attributeChanges: [] };
    },
  };
  return { source, calls };
}

const START = parseEthrDid(`did:ethr:${addressAt(0)}`);

async function failureOf(promise: Promise<unknown>): Promise<VericertsError> {
  try {
    await promise;
  } catch (error) {
    return error as VericertsError;
  }
  throw new Error('should have thrown');
}

describe('detectController: 段数上限', () => {
  test.each([
    1,
    2,
    3,
    MAX_CONTROLLER_CHAIN_DEPTH,
  ])('正当な %i 段の連鎖は従来どおり解決できる', async (hops) => {
    const { source, calls } = chainOf(hops);
    expect(await detectController(START, source)).toBe(`did:ethr:${addressAt(hops)}`);
    // 各段 + 終端の確認で hops + 1 回。
    expect(calls).toHaveLength(hops + 1);
  });

  test.each([
    MAX_CONTROLLER_CHAIN_DEPTH + 1,
    MAX_CONTROLLER_CHAIN_DEPTH + 2,
    100,
    10_000,
  ])('%i 段の連鎖は上限の段で止まり、それ以降の RPC を発行しない', async (hops) => {
    const { source, calls } = chainOf(hops);
    const error = await failureOf(detectController(START, source));
    expect(error.code).toBe(ErrorCodes.INVALID_DID);
    expect(error.context?.reason).toBe('resolution_work_limit');
    // 照会は段数上限 + 1 回（起点 + 各段）で止まる。連鎖の長さに依らず一定。
    expect(calls).toHaveLength(MAX_CONTROLLER_CHAIN_DEPTH + 1);
  });

  test('上限ぴったりの連鎖の最上位は解決できる', async () => {
    const { source } = chainOf(MAX_CONTROLLER_CHAIN_DEPTH);
    expect(await detectController(START, source)).toBe(
      `did:ethr:${addressAt(MAX_CONTROLLER_CHAIN_DEPTH)}`,
    );
  });
});

describe('detectController: 仕事量の予算', () => {
  test('1 段ごとに RPC 往復ぶんを取得の前に計上する', async () => {
    const { source } = chainOf(2);
    const scope = createResolutionWorkBudget(10 * WORK_UNITS_PER_OWNER_LOOKUP);
    await detectController(START, source, scope);
    // 起点 + 1 段 + 終端の 3 照会ぶん。
    expect(scope.remaining).toBe(7 * WORK_UNITS_PER_OWNER_LOOKUP);
  });

  test.each([
    [1, 1],
    [2, 2],
    [3, 3],
  ])('残りが %i 照会ぶんしかないスコープは、その照会回数で打ち切る（長い連鎖でも）', async (budgeted, expectedCalls) => {
    const { source, calls } = chainOf(3);
    const scope = createResolutionWorkBudget(budgeted * WORK_UNITS_PER_OWNER_LOOKUP);
    const error = await failureOf(detectController(START, source, scope));
    expect(error.code).toBe(ErrorCodes.INVALID_DID);
    expect(error.context?.reason).toBe('resolution_work_limit');
    expect(calls).toHaveLength(expectedCalls);
  });

  test('尽きたスコープでは 1 回も RPC を発行しない', async () => {
    const { source, calls } = chainOf(1);
    const scope = createResolutionWorkBudget(0);
    const error = await failureOf(detectController(START, source, scope));
    expect(error.context?.reason).toBe('resolution_work_limit');
    expect(calls).toHaveLength(0);
  });

  test('fetchEvents へ同じスコープを渡す（イベントのデコード量が同じ予算に載る）', async () => {
    const seen: unknown[] = [];
    const source: Erc1056EventSource = {
      async fetchEvents(_chainId, _address, scope) {
        seen.push(scope);
        return { ownerChanges: [], attributeChanges: [] };
      },
    };
    const scope = createResolutionWorkBudget();
    await failureOf(detectController(START, source, scope));
    expect(seen).toEqual([scope]);
  });
});
