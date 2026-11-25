/**
 * `emergencyRevoke` のレシート待機ループ（`waitForReceipt`）の回数・間隔。
 *
 * 入口検証だけでは、ループ自体を壊しても（`attempt < 1` / `<=` / `maxAttempts - 1` /
 * sleep 省略）全テストが通る。ここで「N 回目に取得できれば成功」「上限 N 回で
 * `receipt_timeout`（`attempts = N`）」「試行の間にだけ `receiptPollIntervalMs` を待つ」を固定する。
 * 待機は `setTimeout` を即時発火するスタブに差し替え、要求された遅延だけを記録する（実時間に依存しない）。
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import type { VericertsError } from '../../../errors.js';
import type { RecoverableSignature } from '../../../keymanager/signer.js';
import type { BundlerRpc } from '../../bundler.js';
import { emergencyRevoke } from '../../emergency-revoke.js';
import {
  ACCOUNT,
  CHAIN_ID,
  fakeBundlerRpc,
  fakeCallSource,
  OTHER_VALIDATOR,
  SIGNING_VALIDATOR,
  TX_HASH,
} from './emergency-revoke.fixtures.js';

const POLL_INTERVAL_MS = 1234;

const fakeSign = async (): Promise<RecoverableSignature> => ({
  signature: new Uint8Array(65),
  recovery: 0,
});

const realSetTimeout = globalThis.setTimeout;
let sleeps: number[] = [];

beforeEach(() => {
  sleeps = [];
  globalThis.setTimeout = ((handler: TimerHandler, delay?: number) => {
    sleeps.push(delay ?? 0);
    (handler as () => void)();
    return 0;
  }) as unknown as typeof globalThis.setTimeout;
});

afterEach(() => {
  globalThis.setTimeout = realSetTimeout;
});

/** 最初の `nullPolls` 回の `eth_getUserOperationReceipt` は `null`、以降は確定済みレシートを返す。 */
function bundlerWithPendingPolls(nullPolls: number): { rpc: BundlerRpc; polls: () => number } {
  const confirmed = fakeBundlerRpc(true);
  let polls = 0;
  return {
    polls: () => polls,
    rpc: {
      async request(method, params) {
        if (method === 'eth_getUserOperationReceipt') {
          polls += 1;
          if (polls <= nullPolls) {
            return null;
          }
        }
        return confirmed.request(method, params);
      },
    },
  };
}

function run(bundlerRpc: BundlerRpc, maxReceiptAttempts: number) {
  return emergencyRevoke({
    callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
    bundlerRpc,
    chainId: CHAIN_ID,
    accountAddress: ACCOUNT,
    signingValidatorAddress: SIGNING_VALIDATOR,
    sign: fakeSign,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 900_000_000n,
    maxReceiptAttempts,
    receiptPollIntervalMs: POLL_INTERVAL_MS,
  });
}

describe('emergencyRevoke — レシート待機ループ', () => {
  test('最初の 2 回が null で 3 回目に取得できれば成功し、poll 3 回・待機 2 回', async () => {
    const { rpc, polls } = bundlerWithPendingPolls(2);

    const result = await run(rpc, 5);

    expect(result.txHash).toBe(TX_HASH);
    expect(polls()).toBe(3);
    expect(sleeps).toEqual([POLL_INTERVAL_MS, POLL_INTERVAL_MS]);
  });

  test('1 回目で取得できれば待機しない', async () => {
    const { rpc, polls } = bundlerWithPendingPolls(0);

    await run(rpc, 5);

    expect(polls()).toBe(1);
    expect(sleeps).toEqual([]);
  });

  test('最後の試行（maxReceiptAttempts 回目）で取得できれば成功する', async () => {
    const { rpc, polls } = bundlerWithPendingPolls(2);

    const result = await run(rpc, 3);

    expect(result.txHash).toBe(TX_HASH);
    expect(polls()).toBe(3);
  });

  test('常に null なら maxReceiptAttempts 回ちょうど問い合わせ、receipt_timeout（attempts = N）で落とす', async () => {
    const { rpc, polls } = bundlerWithPendingPolls(Number.POSITIVE_INFINITY);

    const error = await run(rpc, 3).catch((e: unknown) => e);

    const context = (error as VericertsError).context;
    expect(context).toMatchObject({ phase: 'receipt_timeout', attempts: 3 });
    expect(context?.userOpHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(polls()).toBe(3);
    // 最後の試行の後は待たない（試行の間の 2 回だけ）。
    expect(sleeps).toEqual([POLL_INTERVAL_MS, POLL_INTERVAL_MS]);
  });
});
