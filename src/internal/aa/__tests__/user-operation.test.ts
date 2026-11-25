/**
 * UserOperation 構築・UserOpHash 計算のユニットテスト。
 *
 * EntryPoint v0.7 の UserOperation が対象。
 */

import { describe, expect, test } from 'bun:test';
import { getUserOperationHash } from 'viem/account-abstraction';
import { VericertsError } from '../../errors.js';
import { ENTRY_POINT_V07_ADDRESS, type Hex, type UserOperationV07 } from '../types.js';
import {
  buildUserOperation,
  EMPTY_SIGNATURE,
  getUserOpHash,
  withUserOperationFields,
} from '../user-operation.js';

const SENDER = '0x1111111111111111111111111111111111111111' as Hex;
const FACTORY = '0x2222222222222222222222222222222222222222' as Hex;
const CALL_DATA = '0xabcdef' as Hex;

function baseInput() {
  return { sender: SENDER, nonce: 0n, callData: CALL_DATA };
}

describe('buildUserOperation', () => {
  test('未指定のガス・fee・署名を既定値で埋める', () => {
    const op = buildUserOperation(baseInput());
    expect(op.sender).toBe(SENDER);
    expect(op.nonce).toBe(0n);
    expect(op.callData).toBe(CALL_DATA);
    expect(op.callGasLimit).toBe(0n);
    expect(op.verificationGasLimit).toBe(0n);
    expect(op.preVerificationGas).toBe(0n);
    expect(op.maxFeePerGas).toBe(0n);
    expect(op.maxPriorityFeePerGas).toBe(0n);
    expect(op.signature).toBe(EMPTY_SIGNATURE);
    expect(op.factory).toBeUndefined();
    expect(op.factoryData).toBeUndefined();
  });

  test('指定したガス・fee・署名・factory を保持する', () => {
    const op = buildUserOperation({
      ...baseInput(),
      factory: FACTORY,
      factoryData: '0x1234' as Hex,
      callGasLimit: 100n,
      verificationGasLimit: 200n,
      preVerificationGas: 300n,
      maxFeePerGas: 400n,
      maxPriorityFeePerGas: 500n,
      signature: '0xdead' as Hex,
    });
    expect(op.factory).toBe(FACTORY);
    expect(op.factoryData).toBe('0x1234');
    expect(op.callGasLimit).toBe(100n);
    expect(op.maxPriorityFeePerGas).toBe(500n);
    expect(op.signature).toBe('0xdead');
  });

  test('factory のみ指定は 4070 で拒否する', () => {
    expect(() => buildUserOperation({ ...baseInput(), factory: FACTORY })).toThrow(VericertsError);
    try {
      buildUserOperation({ ...baseInput(), factory: FACTORY });
    } catch (e) {
      expect((e as VericertsError).code).toBe('4070');
    }
  });

  test('factoryData のみ指定は 4070 で拒否する', () => {
    expect(() => buildUserOperation({ ...baseInput(), factoryData: '0x1234' as Hex })).toThrow(
      VericertsError,
    );
  });
});

describe('withUserOperationFields', () => {
  test('指定フィールドのみを上書きし他は保持する', () => {
    const op = buildUserOperation(baseInput());
    const patched = withUserOperationFields(op, {
      callGasLimit: 999n,
      signature: '0xbeef' as Hex,
    });
    expect(patched.callGasLimit).toBe(999n);
    expect(patched.signature).toBe('0xbeef');
    expect(patched.sender).toBe(SENDER);
    // 元オブジェクトは不変。
    expect(op.callGasLimit).toBe(0n);
  });
});

describe('getUserOpHash', () => {
  const filledOp: UserOperationV07 = {
    sender: SENDER,
    nonce: 1n,
    callData: CALL_DATA,
    callGasLimit: 100_000n,
    verificationGasLimit: 200_000n,
    preVerificationGas: 50_000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    signature: EMPTY_SIGNATURE,
  };

  test('viem の getUserOperationHash（EntryPoint v0.7）と一致する', () => {
    const expected = getUserOperationHash({
      chainId: 1,
      entryPointAddress: ENTRY_POINT_V07_ADDRESS,
      entryPointVersion: '0.7',
      userOperation: filledOp,
    });
    expect(getUserOpHash(filledOp, 1)).toBe(expected);
  });

  test('paymaster 系・factory 系を自身に持つ op でも viem の getUserOperationHash と一致する', () => {
    const op: UserOperationV07 = {
      ...filledOp,
      factory: SENDER,
      factoryData: '0xfac7' as Hex,
      paymaster: SENDER,
      paymasterVerificationGasLimit: 10n,
      paymasterPostOpGasLimit: 20n,
      paymasterData: '0xab' as Hex,
    };
    const expected = getUserOperationHash({
      chainId: 1,
      entryPointAddress: ENTRY_POINT_V07_ADDRESS,
      entryPointVersion: '0.7',
      userOperation: op,
    });
    expect(getUserOpHash(op, 1)).toBe(expected);
  });

  test('32 バイト hash を返す', () => {
    const hash = getUserOpHash(filledOp, 1);
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  test('chainId によって hash が変わる（リプレイ防止バインド）', () => {
    expect(getUserOpHash(filledOp, 1)).not.toBe(getUserOpHash(filledOp, 42161));
  });

  test('署名は hash に影響しない', () => {
    const signed = withUserOperationFields(filledOp, { signature: '0xdeadbeef' as Hex });
    expect(getUserOpHash(signed, 1)).toBe(getUserOpHash(filledOp, 1));
  });

  test('nonce が変わると hash が変わる', () => {
    const other = withUserOperationFields(filledOp, { nonce: 2n });
    expect(getUserOpHash(other, 1)).not.toBe(getUserOpHash(filledOp, 1));
  });
});
