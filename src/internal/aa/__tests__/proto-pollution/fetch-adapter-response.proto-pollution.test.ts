/**
 * `createFetchBundlerRpc` / `createFetchPaymasterClient` の `Object.prototype` 汚染耐性
 * テスト。
 *
 * 両アダプタは `response.json()`（`Object.prototype` を継承する通常の `JSON.parse`）を使い、
 * `payload` / `body.result` をそのまま `estimateUserOperationGas` / `getUserOperationReceipt`
 * （bundler.ts）・`normalizePaymasterFields`（paymaster.ts）へドット記法で渡していた。
 * `Object.prototype` が汚染された状態で Bundler / Paymaster がフィールドを欠くレスポンスを
 * 返すと、欠落値のはずが汚染値にすり替わって `fromHex` の型検査を通過してしまう
 * （fail-open）。`parseJsonWithoutPrototype` を通せば、欠落フィールドは常に `undefined` になり `CHAIN_SUBMIT_FAILED`（1021）で
 * fail-closed に拒否される。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { estimateUserOperationGas, getUserOperationReceipt } from '../../bundler.js';
import { createFetchBundlerRpc, type FetchLike } from '../../fetch-adapter.js';
import { createFetchPaymasterClient } from '../../paymaster-fetch-adapter.js';
import type { Hex, UserOperationV07 } from '../../types.js';

const BUNDLER_URL = 'https://bundler.example/rpc';
const PAYMASTER_URL = 'https://paymaster.example/rpc';

const SENDER = '0x1111111111111111111111111111111111111111' as Hex;
const ATTACKER_PAYMASTER = '0x2222222222222222222222222222222222222222' as Hex;

const USER_OP: UserOperationV07 = {
  sender: SENDER,
  nonce: 0n,
  callData: '0xabcdef' as Hex,
  callGasLimit: 0n,
  verificationGasLimit: 0n,
  preVerificationGas: 0n,
  maxFeePerGas: 0n,
  maxPriorityFeePerGas: 0n,
  signature: '0x' as Hex,
};

/** JSON-RPC リクエストの `id` をそのまま返す `result` テキストを返す fake fetch。 */
function fakeJsonRpcFetch(result: unknown): FetchLike {
  return async (_input, init) => {
    const req = JSON.parse(init.body) as { id: number };
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
}

/** VericertsError であり code が一致することを検証する。 */
async function expectChainSubmitFailed(promise: Promise<unknown>): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
}

describe('Bundler / Paymaster レスポンスの Object.prototype 汚染耐性', () => {
  test('estimateUserOperationGas: 欠落した gas フィールドは汚染値を拾わず 1021 で拒否される', async () => {
    const rpc = createFetchBundlerRpc(BUNDLER_URL, fakeJsonRpcFetch({}));
    await withPollutedPrototypeAsync(
      {
        preVerificationGas: '0x99999',
        verificationGasLimit: '0x99999',
        callGasLimit: '0x99999',
      },
      () => expectChainSubmitFailed(estimateUserOperationGas(rpc, USER_OP)),
    );
  });

  test('getUserOperationReceipt: 欠落した actualGasUsed/actualGasCost は汚染値を拾わず 1021 で拒否される', async () => {
    const rpc = createFetchBundlerRpc(
      BUNDLER_URL,
      fakeJsonRpcFetch({
        userOpHash: '0xhash',
        transactionHash: '0xtx',
        success: true,
        // actualGasUsed / actualGasCost を意図的に欠落させる。
      }),
    );
    await withPollutedPrototypeAsync({ actualGasUsed: '0x99999', actualGasCost: '0x99999' }, () =>
      expectChainSubmitFailed(getUserOperationReceipt(rpc, '0xhash' as Hex)),
    );
  });

  test('getPaymasterData: 欠落した paymaster/paymasterData は汚染値を拾わず 1021 で拒否される', async () => {
    const client = createFetchPaymasterClient(PAYMASTER_URL, fakeJsonRpcFetch({}));
    await withPollutedPrototypeAsync(
      {
        paymaster: ATTACKER_PAYMASTER,
        paymasterData: '0xdead',
      },
      () => expectChainSubmitFailed(client.getPaymasterData(USER_OP, 1)),
    );
  });

  test('getPaymasterStubData: 欠落した paymaster/paymasterData は汚染値を拾わず 1021 で拒否される', async () => {
    const client = createFetchPaymasterClient(PAYMASTER_URL, fakeJsonRpcFetch({}));
    await withPollutedPrototypeAsync(
      {
        paymaster: ATTACKER_PAYMASTER,
        paymasterData: '0xdead',
      },
      () => expectChainSubmitFailed(client.getPaymasterStubData(USER_OP, 1)),
    );
  });
});
