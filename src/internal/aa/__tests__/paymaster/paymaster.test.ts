/**
 * Paymaster（ガス代代払い）連携のユニットテスト（fake PaymasterClient 注入）。
 *
 * Paymaster サービスへの RPC 呼び出しはスタブで検証する。
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import {
  applyPaymasterFields,
  normalizePaymasterFields,
  type PaymasterClient,
  type PaymasterFields,
  sponsorUserOperation,
} from '../../paymaster.js';
import type { Hex, UserOperationV07 } from '../../types.js';

const SENDER = '0x1111111111111111111111111111111111111111' as Hex;
const PAYMASTER = '0x2222222222222222222222222222222222222222' as Hex;

const OP: UserOperationV07 = {
  sender: SENDER,
  nonce: 5n,
  callData: '0xabcdef' as Hex,
  callGasLimit: 100_000n,
  verificationGasLimit: 200_000n,
  preVerificationGas: 50_000n,
  maxFeePerGas: 1_000_000_000n,
  maxPriorityFeePerGas: 900_000_000n,
  signature: '0x' as Hex,
};

const FULL_FIELDS: PaymasterFields = {
  paymaster: PAYMASTER,
  paymasterData: '0xdeadbeef' as Hex,
  paymasterVerificationGasLimit: 30_000n,
  paymasterPostOpGasLimit: 10_000n,
};

/** 呼び出しを記録する fake PaymasterClient。 */
function fakeClient(fields: PaymasterFields): {
  client: PaymasterClient;
  calls: { method: 'stub' | 'data'; chainId: number }[];
} {
  const calls: { method: 'stub' | 'data'; chainId: number }[] = [];
  return {
    calls,
    client: {
      async getPaymasterStubData(_userOp, chainId) {
        calls.push({ method: 'stub', chainId });
        return fields;
      },
      async getPaymasterData(_userOp, chainId) {
        calls.push({ method: 'data', chainId });
        return fields;
      },
    },
  };
}

describe('applyPaymasterFields', () => {
  test('paymaster フィールド一式を付与する', () => {
    const result = applyPaymasterFields(OP, FULL_FIELDS);
    expect(result.paymaster).toBe(PAYMASTER);
    expect(result.paymasterData).toBe('0xdeadbeef');
    expect(result.paymasterVerificationGasLimit).toBe(30_000n);
    expect(result.paymasterPostOpGasLimit).toBe(10_000n);
    // 元フィールドは保持する。
    expect(result.sender).toBe(SENDER);
    expect(result.callGasLimit).toBe(100_000n);
  });

  test('gas 上限を Paymaster が返さない場合は元の値を保持する', () => {
    const withGas: UserOperationV07 = {
      ...OP,
      paymasterVerificationGasLimit: 77n,
      paymasterPostOpGasLimit: 88n,
    };
    const result = applyPaymasterFields(withGas, {
      paymaster: PAYMASTER,
      paymasterData: '0x01' as Hex,
    });
    expect(result.paymaster).toBe(PAYMASTER);
    expect(result.paymasterVerificationGasLimit).toBe(77n);
    expect(result.paymasterPostOpGasLimit).toBe(88n);
  });

  test('元 UserOp を破壊的に変更しない', () => {
    applyPaymasterFields(OP, FULL_FIELDS);
    expect(OP.paymaster).toBeUndefined();
  });
});

describe('sponsorUserOperation', () => {
  test('既定（本データ）は getPaymasterData を呼び付与する', async () => {
    const { client, calls } = fakeClient(FULL_FIELDS);
    const sponsored = await sponsorUserOperation(client, OP, 1);
    expect(calls).toEqual([{ method: 'data', chainId: 1 }]);
    expect(sponsored.paymaster).toBe(PAYMASTER);
    expect(sponsored.paymasterData).toBe('0xdeadbeef');
  });

  test('stub オプションで getPaymasterStubData を呼ぶ', async () => {
    const { client, calls } = fakeClient(FULL_FIELDS);
    const sponsored = await sponsorUserOperation(client, OP, 137, { stub: true });
    expect(calls).toEqual([{ method: 'stub', chainId: 137 }]);
    expect(sponsored.paymaster).toBe(PAYMASTER);
  });

  test('Paymaster 由来の例外はそのまま伝播する', async () => {
    const err = new VericertsError('1021');
    const client: PaymasterClient = {
      async getPaymasterStubData() {
        throw err;
      },
      async getPaymasterData() {
        throw err;
      },
    };
    await expect(sponsorUserOperation(client, OP, 1)).rejects.toBe(err);
  });
});

describe('normalizePaymasterFields', () => {
  test('paymaster / paymasterData と gas 上限を正規化する', () => {
    const fields = normalizePaymasterFields({
      paymaster: PAYMASTER,
      paymasterData: '0xaa',
      paymasterVerificationGasLimit: '0x7530',
      paymasterPostOpGasLimit: '0x2710',
    });
    expect(fields.paymaster).toBe(PAYMASTER);
    expect(fields.paymasterData).toBe('0xaa');
    expect(fields.paymasterVerificationGasLimit).toBe(30_000n);
    expect(fields.paymasterPostOpGasLimit).toBe(10_000n);
  });

  test('gas 上限が無い場合は省略する', () => {
    const fields = normalizePaymasterFields({
      paymaster: PAYMASTER,
      paymasterData: '0x00',
    });
    expect(fields.paymasterVerificationGasLimit).toBeUndefined();
    expect(fields.paymasterPostOpGasLimit).toBeUndefined();
  });

  test('paymaster 欠落は 1021 に正規化する', () => {
    expect(() => normalizePaymasterFields({ paymasterData: '0x00' })).toThrow(VericertsError);
  });

  test('paymasterData が hex でない場合は 1021', () => {
    expect(() => normalizePaymasterFields({ paymaster: PAYMASTER, paymasterData: 'nope' })).toThrow(
      VericertsError,
    );
  });

  test.each([
    ['短い paymaster（20 バイトでない）', { paymaster: '0x1234', paymasterData: '0xaa' }],
    ['長すぎる paymaster', { paymaster: `${PAYMASTER}00`, paymasterData: '0xaa' }],
    ['非 hex の paymaster', { paymaster: `0x${'zz'.repeat(20)}`, paymasterData: '0xaa' }],
    [
      '非 hex の paymasterData（0x 接頭辞のみ満たす）',
      { paymaster: PAYMASTER, paymasterData: '0xzz' },
    ],
    ['奇数長の paymasterData', { paymaster: PAYMASTER, paymasterData: '0xabc' }],
  ])('0x で始まっても形状不正なら 1021: %s', (_name, fields) => {
    expect(() => normalizePaymasterFields(fields)).toThrow(VericertsError);
    expect(() => normalizePaymasterFields(fields)).toThrow(
      expect.objectContaining({ code: '1021' }),
    );
  });

  test('空の paymasterData（0x）と大文字 hex は受理する', () => {
    const fields = normalizePaymasterFields({
      paymaster: `0x${'AB'.repeat(20)}`,
      paymasterData: '0x',
    });
    expect(fields.paymasterData).toBe('0x');
  });

  test('object でない戻り値は 1021', () => {
    expect(() => normalizePaymasterFields(null)).toThrow(VericertsError);
  });

  test('gas 上限が hex でない場合は 1021', () => {
    expect(() =>
      normalizePaymasterFields({
        paymaster: PAYMASTER,
        paymasterData: '0x00',
        paymasterVerificationGasLimit: 123,
      }),
    ).toThrow(VericertsError);
  });
});
