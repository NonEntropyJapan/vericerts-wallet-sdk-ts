/**
 * UserOperation の任意 paymaster フィールドの `Object.prototype` 汚染耐性テスト。
 *
 * `UserOperationV07` は `@vericerts/vericerts-wallet-sdk/aa` から公開され、呼び出し側が組み立てた値をそのまま
 * 受け取る。任意フィールド（`paymaster` / `paymasterData` / paymaster のガス上限）をプロトタイプ鎖で
 * 読むと、それらを**省略した**正当な UserOperation でも汚染値が Bundler へ送る表現・予算検査・
 * 署名対象へ入る。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { toRpcUserOperation } from '../../bundler.js';
import { assertTotalGasCostWithin } from '../../gas-limits.js';
import { applyPaymasterFields, type PaymasterFields } from '../../paymaster.js';
import type { Hex } from '../../types.js';
import { buildUserOperation } from '../../user-operation.js';

const SENDER = '0x1111111111111111111111111111111111111111' as Hex;
const PAYMASTER = '0x2222222222222222222222222222222222222222' as Hex;
const ATTACKER = '0x3333333333333333333333333333333333333333' as Hex;

const userOp = buildUserOperation({
  sender: SENDER,
  nonce: 0n,
  callData: '0xdeadbeef',
  callGasLimit: 100n,
  verificationGasLimit: 200n,
  preVerificationGas: 300n,
  maxFeePerGas: 2n,
});
/** paymaster 分を含まない最悪ケースの prefund（(100 + 200 + 300) × 2）。 */
const EXACT_BUDGET = 1_200n;

const POLLUTION = {
  paymaster: ATTACKER,
  paymasterData: '0xbad0',
  paymasterVerificationGasLimit: 12_345n,
  paymasterPostOpGasLimit: 6_789n,
};

describe('paymaster フィールドの Object.prototype 汚染耐性', () => {
  it('toRpcUserOperation: 継承した paymaster 系フィールドを Bundler 送信表現へ載せない', () => {
    const clean = toRpcUserOperation(userOp);
    const polluted = withPollutedPrototype(POLLUTION, () => toRpcUserOperation(userOp));
    expect(polluted).toEqual(clean);
    expect(Object.keys(polluted).filter((key) => key.startsWith('paymaster'))).toEqual([]);
  });

  it('assertTotalGasCostWithin: 継承した paymaster ガス上限を予算計算に足さない', () => {
    expect(() =>
      withPollutedPrototype(POLLUTION, () => assertTotalGasCostWithin(userOp, EXACT_BUDGET)),
    ).not.toThrow();
  });

  it('applyPaymasterFields: 継承した paymaster ガス上限を引き継がない', () => {
    // プロトタイプを持たない fields で、userOp 側の読み取りだけを検査対象にする。
    // `applyPaymasterFields` / `assertGasWithinLimits` は fields 側（`PaymasterFields`）の任意フィールドを
    // まだプロトタイプ鎖で読むため、通常のオブジェクトでは汚染値が入る。fields 側（`PaymasterFields`）の
    // 継承読みは別のテストで確認する。
    const fields = Object.assign(Object.create(null) as object, {
      paymaster: PAYMASTER,
      paymasterData: '0x' as Hex,
    }) as PaymasterFields;
    const applied = withPollutedPrototype(POLLUTION, () => applyPaymasterFields(userOp, fields));
    expect(applied.paymaster).toBe(PAYMASTER);
    expect(applied.paymasterVerificationGasLimit).toBeUndefined();
    expect(applied.paymasterPostOpGasLimit).toBeUndefined();
  });

  it('自身に持つ paymaster 系フィールドは従来どおり使う（正常系）', () => {
    const sponsored = {
      ...userOp,
      paymaster: PAYMASTER,
      paymasterVerificationGasLimit: 10n,
      paymasterPostOpGasLimit: 20n,
    };
    expect(toRpcUserOperation(sponsored)).toMatchObject({
      paymaster: PAYMASTER,
      paymasterVerificationGasLimit: '0xa',
      paymasterPostOpGasLimit: '0x14',
      paymasterData: '0x',
    });
    expect(() => assertTotalGasCostWithin(sponsored, EXACT_BUDGET + 60n)).not.toThrow();
    expect(() => assertTotalGasCostWithin(sponsored, EXACT_BUDGET + 59n)).toThrow();
    const fields = { paymaster: PAYMASTER, paymasterData: '0x' as Hex };
    const applied = applyPaymasterFields(sponsored, fields);
    expect(applied.paymasterVerificationGasLimit).toBe(10n);
    expect(applied.paymasterPostOpGasLimit).toBe(20n);
  });
});
