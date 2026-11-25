/**
 * Bundler JSON-RPC 通信のユニットテスト（fake BundlerRpc 注入）。
 *
 * Bundler との RPC 呼び出しはスタブで検証する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { createInMemoryMetrics, MetricNames } from '../../observability/metrics.js';
import type { BundlerRpc } from '../bundler.js';
import {
  estimateUserOperationGas,
  getSupportedEntryPoints,
  getUserOperationReceipt,
  sendUserOperation,
  toRpcUserOperation,
} from '../bundler.js';
import { ENTRY_POINT_V07_ADDRESS, type Hex, type UserOperationV07 } from '../types.js';

const SENDER = '0x1111111111111111111111111111111111111111' as Hex;

const OP: UserOperationV07 = {
  sender: SENDER,
  nonce: 5n,
  callData: '0xabcdef' as Hex,
  callGasLimit: 100_000n,
  verificationGasLimit: 200_000n,
  preVerificationGas: 50_000n,
  maxFeePerGas: 1_000_000_000n,
  maxPriorityFeePerGas: 900_000_000n,
  signature: '0xdead' as Hex,
};

/** 記録付き fake BundlerRpc。 */
function fakeRpc(result: unknown): {
  rpc: BundlerRpc;
  calls: { method: string; params: readonly unknown[] }[];
} {
  const calls: { method: string; params: readonly unknown[] }[] = [];
  return {
    calls,
    rpc: {
      async request(method, params) {
        calls.push({ method, params });
        return result;
      },
    },
  };
}

function throwingRpc(err: unknown): BundlerRpc {
  return {
    async request() {
      throw err;
    },
  };
}

describe('toRpcUserOperation', () => {
  test('数値フィールドを hex 化し factory / paymaster は省略する', () => {
    const rpc = toRpcUserOperation(OP);
    expect(rpc.sender).toBe(SENDER);
    expect(rpc.nonce).toBe('0x5');
    expect(rpc.callGasLimit).toBe('0x186a0');
    expect(rpc.maxFeePerGas).toBe('0x3b9aca00');
    expect(rpc.signature).toBe('0xdead');
    expect(rpc.factory).toBeUndefined();
    expect(rpc.paymaster).toBeUndefined();
  });

  test('factory / factoryData をセットで含める', () => {
    const rpc = toRpcUserOperation({
      ...OP,
      factory: SENDER,
      factoryData: '0x1234' as Hex,
    });
    expect(rpc.factory).toBe(SENDER);
    expect(rpc.factoryData).toBe('0x1234');
  });

  test('paymaster 設定時は付随フィールドを hex 化する', () => {
    const rpc = toRpcUserOperation({
      ...OP,
      paymaster: SENDER,
      paymasterVerificationGasLimit: 111n,
      paymasterPostOpGasLimit: 222n,
      paymasterData: '0xaa' as Hex,
    });
    expect(rpc.paymaster).toBe(SENDER);
    expect(rpc.paymasterVerificationGasLimit).toBe('0x6f');
    expect(rpc.paymasterPostOpGasLimit).toBe('0xde');
    expect(rpc.paymasterData).toBe('0xaa');
  });
});

describe('sendUserOperation', () => {
  test('eth_sendUserOperation に UserOp と EntryPoint を渡し hash を返す', async () => {
    const hash = '0xhash' as const;
    const { rpc, calls } = fakeRpc(`${hash}`);
    const result = await sendUserOperation(rpc, OP);
    expect(result).toBe(hash);
    expect(calls[0]?.method).toBe('eth_sendUserOperation');
    expect(calls[0]?.params[1]).toBe(ENTRY_POINT_V07_ADDRESS);
    expect((calls[0]?.params[0] as Record<string, string>).nonce).toBe('0x5');
  });

  test('hex でない戻り値は 1021 に正規化する', async () => {
    const { rpc } = fakeRpc(12345);
    await expect(sendUserOperation(rpc, OP)).rejects.toThrow(VericertsError);
  });

  test('RPC 例外はそのまま伝播する', async () => {
    const err = new VericertsError('1021');
    await expect(sendUserOperation(throwingRpc(err), OP)).rejects.toBe(err);
  });

  test('metrics 注入時、成功で vericerts_bundler_userop_total{result=success} を記録する', async () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    const { rpc } = fakeRpc('0xhash');

    await sendUserOperation(rpc, OP, metrics);

    expect(
      snapshot().counters.find(
        (c) => c.name === MetricNames.BUNDLER_USEROP_TOTAL && c.labels.result === 'success',
      )?.value,
    ).toBe(1);
  });

  test('metrics 注入時、失敗で vericerts_bundler_userop_total{result=failure} を記録する', async () => {
    const { metrics, snapshot } = createInMemoryMetrics();
    const err = new VericertsError('1021');

    await expect(sendUserOperation(throwingRpc(err), OP, metrics)).rejects.toBe(err);

    expect(
      snapshot().counters.find(
        (c) => c.name === MetricNames.BUNDLER_USEROP_TOTAL && c.labels.result === 'failure',
      )?.value,
    ).toBe(1);
  });

  test('metrics sink が throw しても送信成功の結果を置換せず failure も計上しない', async () => {
    const { rpc, calls } = fakeRpc('0xhash');
    const incs: string[] = [];
    const metrics = {
      counter: (_name: string, labels: Record<string, string>) => ({
        inc: () => {
          incs.push(labels.result ?? '');
          throw new Error('metrics backend down');
        },
      }),
    } as unknown as Parameters<typeof sendUserOperation>[2];

    await expect(sendUserOperation(rpc, OP, metrics)).resolves.toBe('0xhash');
    expect(calls).toHaveLength(1);
    expect(incs).toEqual(['success']);
  });

  test('metrics sink が throw しても RPC の元エラーを置換しない', async () => {
    const err = new VericertsError('1021');
    const metrics = {
      counter: () => ({
        inc: () => {
          throw new Error('metrics backend down');
        },
      }),
    } as unknown as Parameters<typeof sendUserOperation>[2];

    await expect(sendUserOperation(throwingRpc(err), OP, metrics)).rejects.toBe(err);
  });

  test('metrics 未指定でも従来どおり動作する', async () => {
    const { rpc } = fakeRpc('0xhash');
    await expect(sendUserOperation(rpc, OP)).resolves.toBe('0xhash');
  });
});

describe('estimateUserOperationGas', () => {
  test('hex 見積もりを bigint に変換する', async () => {
    const { rpc } = fakeRpc({
      preVerificationGas: '0xc350',
      verificationGasLimit: '0x30d40',
      callGasLimit: '0x186a0',
    });
    const est = await estimateUserOperationGas(rpc, OP);
    expect(est.preVerificationGas).toBe(50_000n);
    expect(est.verificationGasLimit).toBe(200_000n);
    expect(est.callGasLimit).toBe(100_000n);
    expect(est.paymasterVerificationGasLimit).toBeUndefined();
  });

  test('paymaster 見積もりフィールドがあれば含める', async () => {
    const { rpc } = fakeRpc({
      preVerificationGas: '0x1',
      verificationGasLimit: '0x2',
      callGasLimit: '0x3',
      paymasterVerificationGasLimit: '0x4',
      paymasterPostOpGasLimit: '0x5',
    });
    const est = await estimateUserOperationGas(rpc, OP);
    expect(est.paymasterVerificationGasLimit).toBe(4n);
    expect(est.paymasterPostOpGasLimit).toBe(5n);
  });

  test('object でない戻り値は 1021', async () => {
    const { rpc } = fakeRpc(null);
    await expect(estimateUserOperationGas(rpc, OP)).rejects.toThrow(VericertsError);
  });
});

describe('getUserOperationReceipt', () => {
  test('未マイニング（null）はそのまま null を返す', async () => {
    const { rpc } = fakeRpc(null);
    expect(await getUserOperationReceipt(rpc, '0xhash' as Hex)).toBeNull();
  });

  test('レシートを正規化して返す', async () => {
    const { rpc } = fakeRpc({
      userOpHash: '0xhash',
      success: true,
      actualGasUsed: '0x186a0',
      actualGasCost: '0x2710',
      receipt: { transactionHash: '0xtx' },
    });
    const receipt = await getUserOperationReceipt(rpc, '0xhash' as Hex);
    expect(receipt?.success).toBe(true);
    expect(receipt?.actualGasUsed).toBe(100_000n);
    expect(receipt?.actualGasCost).toBe(10_000n);
    expect(receipt?.transactionHash).toBe('0xtx');
  });

  test('要求と異なる userOpHash のレシートは 1021 で拒否する', async () => {
    const requested = `0x${'aa'.repeat(32)}` as Hex;
    const { rpc } = fakeRpc({
      userOpHash: `0x${'bb'.repeat(32)}`,
      success: true,
      actualGasUsed: '0x1',
      actualGasCost: '0x2',
      receipt: { transactionHash: `0x${'cc'.repeat(32)}` },
    });
    const error = await getUserOperationReceipt(rpc, requested).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.CHAIN_SUBMIT_FAILED);
    expect((error as VericertsError).context?.phase).toBe('receipt_userop_hash_mismatch');
  });

  test('userOpHash は大文字小文字を区別せず一致とみなす', async () => {
    const { rpc } = fakeRpc({
      userOpHash: `0x${'AB'.repeat(32)}`,
      success: true,
      actualGasUsed: '0x1',
      actualGasCost: '0x2',
      receipt: { transactionHash: '0xtx' },
    });
    const receipt = await getUserOperationReceipt(rpc, `0x${'ab'.repeat(32)}` as Hex);
    expect(receipt?.success).toBe(true);
  });

  test('必須フィールド欠落は 1021', async () => {
    const { rpc } = fakeRpc({ success: true });
    await expect(getUserOperationReceipt(rpc, '0xhash' as Hex)).rejects.toThrow(VericertsError);
  });
});

describe('getSupportedEntryPoints', () => {
  test('文字列配列を返す', async () => {
    const { rpc, calls } = fakeRpc([ENTRY_POINT_V07_ADDRESS]);
    const eps = await getSupportedEntryPoints(rpc);
    expect(eps).toEqual([ENTRY_POINT_V07_ADDRESS]);
    expect(calls[0]?.method).toBe('eth_supportedEntryPoints');
  });

  test('配列でない戻り値は 1021', async () => {
    const { rpc } = fakeRpc('nope');
    await expect(getSupportedEntryPoints(rpc)).rejects.toThrow(VericertsError);
  });
});
