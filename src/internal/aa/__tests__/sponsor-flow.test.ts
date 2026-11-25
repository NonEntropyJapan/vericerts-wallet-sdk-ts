/**
 * ガススポンサーフローの統合テスト。
 *
 * Paymaster が UserOperation のガス代を引き受けるケースを検証する。
 *
 * ERC-7677 の 2 段階フローを fake seam で通しで検証する:
 *   1. Paymaster スタブ取得 → 付与 → Bundler ガス見積もり → 反映
 *   2. Paymaster 本データ取得 → 付与 → Bundler 送信
 * 実 RPC 非依存。UserOp が最終的に Bundler へ paymaster 付きで送信されることを確認する。
 */

import { describe, expect, test } from 'bun:test';
import type { BundlerRpc } from '../bundler.js';
import { estimateUserOperationGas, sendUserOperation, toRpcUserOperation } from '../bundler.js';
import { type PaymasterClient, type PaymasterFields, sponsorUserOperation } from '../paymaster.js';
import type { Hex, UserOperationV07 } from '../types.js';
import { buildUserOperation, withUserOperationFields } from '../user-operation.js';

const SENDER = '0x1111111111111111111111111111111111111111' as Hex;
const PAYMASTER = '0x2222222222222222222222222222222222222222' as Hex;
const CHAIN_ID = 137;

const STUB: PaymasterFields = {
  paymaster: PAYMASTER,
  paymasterData: '0xstub' as Hex,
  paymasterVerificationGasLimit: 30_000n,
  paymasterPostOpGasLimit: 10_000n,
};

const FINAL: PaymasterFields = {
  paymaster: PAYMASTER,
  paymasterData: '0xsigneddata' as Hex,
  paymasterVerificationGasLimit: 35_000n,
  paymasterPostOpGasLimit: 12_000n,
};

/** スタブ→本データを順に返す fake PaymasterClient。 */
function fakePaymaster(): PaymasterClient {
  return {
    async getPaymasterStubData() {
      return STUB;
    },
    async getPaymasterData() {
      return FINAL;
    },
  };
}

describe('gas スポンサーフロー（統合）', () => {
  test('スタブ→見積もり→本データ→送信で paymaster 付き UserOp を Bundler に渡す', async () => {
    const paymaster = fakePaymaster();

    // 見積もりで gas を返し、送信された UserOp を記録する fake Bundler。
    const sent: Record<string, string>[] = [];
    const bundler: BundlerRpc = {
      async request(method, params) {
        if (method === 'eth_estimateUserOperationGas') {
          return {
            preVerificationGas: '0xc350',
            verificationGasLimit: '0x30d40',
            callGasLimit: '0x186a0',
            paymasterVerificationGasLimit: '0x88b8',
            paymasterPostOpGasLimit: '0x2ee0',
          };
        }
        if (method === 'eth_sendUserOperation') {
          sent.push(params[0] as Record<string, string>);
          return '0xuserophash';
        }
        throw new Error(`unexpected method ${method}`);
      },
    };

    // 1. 未見積もりの UserOp を構築。
    const base = buildUserOperation({
      sender: SENDER,
      nonce: 5n,
      callData: '0xabcdef' as Hex,
      maxFeePerGas: 1_000_000_000n,
      maxPriorityFeePerGas: 900_000_000n,
    });
    expect(base.paymaster).toBeUndefined();

    // 2. スタブ付与（ガス見積もり用に paymaster フィールドを仮置き）。
    const withStub = await sponsorUserOperation(paymaster, base, CHAIN_ID, { stub: true });
    expect(withStub.paymaster).toBe(PAYMASTER);
    expect(withStub.paymasterData).toBe('0xstub');

    // 3. Bundler で見積もり → 実行 gas を反映。
    const estimate = await estimateUserOperationGas(bundler, withStub);
    const estimated = withUserOperationFields(withStub, {
      preVerificationGas: estimate.preVerificationGas,
      verificationGasLimit: estimate.verificationGasLimit,
      callGasLimit: estimate.callGasLimit,
    });
    expect(estimated.callGasLimit).toBe(100_000n);

    // 4. 本データ取得で最終 paymaster 署名を付与。
    const sponsored = await sponsorUserOperation(paymaster, estimated, CHAIN_ID);
    expect(sponsored.paymasterData).toBe('0xsigneddata');
    expect(sponsored.paymasterVerificationGasLimit).toBe(35_000n);

    // 5. 署名を載せて Bundler に送信。
    const signed: UserOperationV07 = withUserOperationFields(sponsored, {
      signature: '0xvalidatorsig' as Hex,
    });
    const hash = await sendUserOperation(bundler, signed);
    expect(hash).toBe('0xuserophash');

    // Bundler に届いた UserOp は paymaster 付きで hexlified されている。
    const rpcOp = sent[0];
    expect(rpcOp?.paymaster).toBe(PAYMASTER);
    expect(rpcOp?.paymasterData).toBe('0xsigneddata');
    expect(rpcOp?.paymasterVerificationGasLimit).toBe('0x88b8');
    expect(rpcOp?.paymasterPostOpGasLimit).toBe('0x2ee0');
    expect(rpcOp?.signature).toBe('0xvalidatorsig');
  });

  test('paymaster 未使用の UserOp は paymaster フィールドが省略される（回帰）', () => {
    const base = buildUserOperation({
      sender: SENDER,
      nonce: 1n,
      callData: '0x' as Hex,
    });
    const rpc = toRpcUserOperation(base);
    expect(rpc.paymaster).toBeUndefined();
    expect(rpc.paymasterData).toBeUndefined();
  });
});
