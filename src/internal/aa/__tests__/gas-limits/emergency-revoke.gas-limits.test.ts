/**
 * Bundler / Paymaster が返すガス値の上限検査。悪意ある Bundler が巨大な見積りを返しても、
 * `emergencyRevoke` が署名・送信に到達しないことを固定する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { RecoverableSignature } from '../../../keymanager/signer.js';
import type { BundlerRpc } from '../../bundler.js';
import { estimateUserOperationGas } from '../../bundler.js';
import { emergencyRevoke } from '../../emergency-revoke.js';
import {
  assertTotalGasCostWithin,
  MAX_CALL_GAS_LIMIT,
  MAX_PAYMASTER_POST_OP_GAS_LIMIT,
  MAX_PAYMASTER_VERIFICATION_GAS_LIMIT,
  MAX_PRE_VERIFICATION_GAS,
  MAX_VERIFICATION_GAS_LIMIT,
} from '../../gas-limits.js';
import { applyPaymasterFields, normalizePaymasterFields } from '../../paymaster.js';
import type { Hex, UserOperationV07 } from '../../types.js';
import {
  ACCOUNT,
  CHAIN_ID,
  fakeBundlerRpc,
  fakeCallSource,
  OTHER_VALIDATOR,
  SIGNING_VALIDATOR,
} from '../emergency-revoke/emergency-revoke.fixtures.js';

const hex = (n: bigint): string => `0x${n.toString(16)}`;

/** 見積りだけ差し替え、送信・レシートは正常な fake に委譲する（PoC と同じ構造）。 */
function bundlerWithEstimate(estimate: Record<string, string>, onSend: () => void): BundlerRpc {
  const honest = fakeBundlerRpc(true, onSend);
  return {
    async request(method, params) {
      if (method === 'eth_estimateUserOperationGas') return estimate;
      return honest.request(method, params);
    },
  };
}

async function revokeWith(
  estimate: Record<string, string>,
  extra: { maxTotalCostWei?: bigint } = {},
): Promise<{ sent: boolean; signed: boolean; error: unknown }> {
  const state = { sent: false, signed: false, error: undefined as unknown };
  const sign = async (): Promise<RecoverableSignature> => {
    state.signed = true;
    return { signature: new Uint8Array(64).fill(1), recovery: 0 };
  };
  try {
    await emergencyRevoke({
      callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
      bundlerRpc: bundlerWithEstimate(estimate, () => {
        state.sent = true;
      }),
      chainId: CHAIN_ID,
      accountAddress: ACCOUNT,
      signingValidatorAddress: SIGNING_VALIDATOR,
      sign,
      maxFeePerGas: 1_000_000_000n,
      maxPriorityFeePerGas: 1n,
      maxReceiptAttempts: 1,
      receiptPollIntervalMs: 0,
      ...extra,
    });
  } catch (e) {
    state.error = e;
  }
  return state;
}

const OK = {
  preVerificationGas: hex(MAX_PRE_VERIFICATION_GAS),
  verificationGasLimit: hex(MAX_VERIFICATION_GAS_LIMIT),
  callGasLimit: hex(MAX_CALL_GAS_LIMIT),
};

function expectRejectedBeforeSigning(r: { sent: boolean; signed: boolean; error: unknown }): void {
  expect(r.error).toBeInstanceOf(VericertsError);
  expect((r.error as VericertsError).code).toBe(ErrorCodes.CHAIN_SUBMIT_FAILED);
  expect(r.signed).toBe(false);
  expect(r.sent).toBe(false);
}

describe('emergencyRevoke のガス上限検査', () => {
  test('上限ちょうどの見積りは署名・送信される', async () => {
    const r = await revokeWith(OK);
    expect(r.error).toBeUndefined();
    expect(r.signed).toBe(true);
    expect(r.sent).toBe(true);
  });

  test('Issue の PoC（巨大な preVerificationGas / verificationGasLimit / callGasLimit）は署名前に拒否', async () => {
    expectRejectedBeforeSigning(
      await revokeWith({
        preVerificationGas: hex(10n ** 9n),
        verificationGasLimit: hex(2n ** 127n),
        callGasLimit: hex(2n ** 127n),
      }),
    );
  });

  test.each([
    ['preVerificationGas', { ...OK, preVerificationGas: hex(MAX_PRE_VERIFICATION_GAS + 1n) }],
    ['verificationGasLimit', { ...OK, verificationGasLimit: hex(MAX_VERIFICATION_GAS_LIMIT + 1n) }],
    ['callGasLimit', { ...OK, callGasLimit: hex(MAX_CALL_GAS_LIMIT + 1n) }],
    [
      'paymasterVerificationGasLimit',
      { ...OK, paymasterVerificationGasLimit: hex(MAX_PAYMASTER_VERIFICATION_GAS_LIMIT + 1n) },
    ],
    [
      'paymasterPostOpGasLimit',
      { ...OK, paymasterPostOpGasLimit: hex(MAX_PAYMASTER_POST_OP_GAS_LIMIT + 1n) },
    ],
  ])('%s が上限を 1 超えたら署名前に拒否する', async (_field, estimate) => {
    expectRejectedBeforeSigning(await revokeWith(estimate));
  });

  test('例外にガス値を含めず、超過フィールド名だけを context に載せる', async () => {
    const r = await revokeWith({ ...OK, callGasLimit: hex(2n ** 100n) });
    const err = r.error as VericertsError;
    expect(JSON.stringify(err.context)).toBe(
      '{"phase":"gas_limit_exceeded","field":"callGasLimit"}',
    );
    expect(err.message).not.toContain(String(2n ** 100n));
  });

  test('maxTotalCostWei: 最悪ケース prefund が予算を超える見積りは署名前に拒否する', async () => {
    const totalGas = MAX_PRE_VERIFICATION_GAS + MAX_VERIFICATION_GAS_LIMIT + MAX_CALL_GAS_LIMIT;
    const maxFeePerGas = 1_000_000_000n;
    expectRejectedBeforeSigning(
      await revokeWith(OK, { maxTotalCostWei: totalGas * maxFeePerGas - 1n }),
    );
    const r = await revokeWith(OK, { maxTotalCostWei: totalGas * maxFeePerGas });
    expect(r.error).toBeUndefined();
  });
});

describe('estimateUserOperationGas / Paymaster 応答の上限検査', () => {
  const OP = {
    sender: ACCOUNT,
    nonce: 0n,
    callData: '0x' as Hex,
    callGasLimit: 0n,
    verificationGasLimit: 0n,
    preVerificationGas: 0n,
    maxFeePerGas: 1n,
    maxPriorityFeePerGas: 1n,
    signature: '0x' as Hex,
  } satisfies UserOperationV07;

  test('estimateUserOperationGas は上限超過の見積りを 1021 で拒否する', async () => {
    const rpc: BundlerRpc = {
      request: async () => ({ ...OK, callGasLimit: hex(MAX_CALL_GAS_LIMIT + 1n) }),
    };
    await expect(estimateUserOperationGas(rpc, OP)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });

  test('normalizePaymasterFields は paymaster ガス上限超過を 1021 で拒否する', () => {
    const base = { paymaster: `0x${'11'.repeat(20)}`, paymasterData: '0x' };
    expect(() =>
      normalizePaymasterFields({
        ...base,
        paymasterPostOpGasLimit: hex(MAX_PAYMASTER_POST_OP_GAS_LIMIT + 1n),
      }),
    ).toThrow(VericertsError);
    expect(
      normalizePaymasterFields({
        ...base,
        paymasterPostOpGasLimit: hex(MAX_PAYMASTER_POST_OP_GAS_LIMIT),
      }).paymasterPostOpGasLimit,
    ).toBe(MAX_PAYMASTER_POST_OP_GAS_LIMIT);
  });

  test('applyPaymasterFields は seam が正規化を通さない巨大値も拒否する', () => {
    expect(() =>
      applyPaymasterFields(OP, {
        paymaster: `0x${'11'.repeat(20)}` as Hex,
        paymasterData: '0x' as Hex,
        paymasterVerificationGasLimit: 2n ** 100n,
      }),
    ).toThrow(VericertsError);
  });

  test('assertTotalGasCostWithin は paymaster 分も合算する', () => {
    const op = {
      ...OP,
      maxFeePerGas: 10n,
      paymasterVerificationGasLimit: 5n,
      paymasterPostOpGasLimit: 5n,
    };
    expect(() => assertTotalGasCostWithin(op, 99n)).toThrow(VericertsError);
    expect(() => assertTotalGasCostWithin(op, 100n)).not.toThrow();
  });
});
