/**
 * `emergencyRevoke` オーケストレーションのユニットテスト。
 * fake の EvmCallSource / BundlerRpc は `emergency-revoke.fixtures.ts`（行数上限のため分離）。
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import type { RecoverableSignature } from '../../../keymanager/signer.js';
import type { BundlerRpc } from '../../bundler.js';
import { emergencyRevoke } from '../../emergency-revoke.js';
import type { Hex } from '../../types.js';
import {
  ACCOUNT,
  CHAIN_ID,
  fakeBundlerRpc,
  fakeCallSource,
  MODULAR_ACCOUNT_IFACE,
  OTHER_VALIDATOR,
  SIGNING_VALIDATOR,
  TX_HASH,
} from './emergency-revoke.fixtures.js';

const fakeSign = async (): Promise<RecoverableSignature> => ({
  signature: new Uint8Array(65),
  recovery: 0,
});

const FEE_DEPS = { maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 900_000_000n };

describe('emergencyRevoke', () => {
  test('署名者以外の Validator を revokedValidators として返し、txHash を返す', async () => {
    const result = await emergencyRevoke({
      callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
      bundlerRpc: fakeBundlerRpc(true),
      chainId: CHAIN_ID,
      accountAddress: ACCOUNT,
      signingValidatorAddress: SIGNING_VALIDATOR,
      sign: fakeSign,
      ...FEE_DEPS,
      maxReceiptAttempts: 1,
      receiptPollIntervalMs: 0,
    });

    expect(result.txHash).toBe(TX_HASH);
    expect(result.revokedValidators).toEqual([OTHER_VALIDATOR]);
    expect(result.newWuaRequired).toBe(true);
  });

  // 閾値は変更しない。`ThresholdUnreachable` は原理的に発生しない（署名者を削除対象から除外して
  // いるため `remaining >= W_署名者 >= threshold` が常に成り立つ）一方、`setThreshold` は閾値を
  // 恒久的に引き上げてしまい、復旧後に weight の小さい新 Validator を追加できなくなる。
  test('callData は uninstallValidator だけの executeBatch（閾値は変更しない）', async () => {
    let sentUserOp: Record<string, unknown> | undefined;
    await emergencyRevoke({
      callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
      bundlerRpc: fakeBundlerRpc(true, (userOp) => {
        sentUserOp = userOp;
      }),
      chainId: CHAIN_ID,
      accountAddress: ACCOUNT,
      signingValidatorAddress: SIGNING_VALIDATOR,
      sign: fakeSign,
      ...FEE_DEPS,
      maxReceiptAttempts: 1,
      receiptPollIntervalMs: 0,
    });

    const callData = sentUserOp?.callData as string;
    const decoded = MODULAR_ACCOUNT_IFACE.decodeFunctionData('executeBatch', callData);
    const [, , func] = decoded as unknown as [string[], bigint[], string[]];
    expect(func).toHaveLength(1);
    const [firstCallData] = func;
    if (firstCallData === undefined) {
      throw new Error('test setup: expected 1 call in executeBatch');
    }
    const first = MODULAR_ACCOUNT_IFACE.parseTransaction({ data: firstCallData });
    expect(first?.name).toBe('uninstallValidator');
    expect((first?.args[0] as string).toLowerCase()).toBe(OTHER_VALIDATOR.toLowerCase());
  });

  // 署名者の weight が閾値未満だと、この UserOp は署名検証フェーズで弾かれる（実行フェーズに
  // 入れないので閾値操作では救えない）。Bundler の不透明な検証失敗にせず送信前に落とす。
  test('署名者の weight が閾値未満なら送信前に 1022 で落とす', async () => {
    await expect(
      emergencyRevoke({
        callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR], {
          signerWeight: 1n,
          threshold: 2n,
        }),
        bundlerRpc: fakeBundlerRpc(true, () => {
          throw new Error('must not send a UserOperation');
        }),
        chainId: CHAIN_ID,
        accountAddress: ACCOUNT,
        signingValidatorAddress: SIGNING_VALIDATOR,
        sign: fakeSign,
        ...FEE_DEPS,
        maxReceiptAttempts: 1,
        receiptPollIntervalMs: 0,
      }),
    ).rejects.toMatchObject({ code: '1022' });
  });

  // 見積りに実署名と同形のダミー署名を載せないと、Validator の staticcall / ecrecover に到達せず
  // verificationGasLimit が過小になる。
  test('ガス見積りは空署名ではなくダミー署名を載せて行う', async () => {
    let estimatedSignature: unknown;
    const base = fakeBundlerRpc(true);
    const spyRpc: BundlerRpc = {
      async request(method: string, params: readonly unknown[]): Promise<unknown> {
        if (method === 'eth_estimateUserOperationGas') {
          estimatedSignature = (params[0] as Record<string, unknown>).signature;
        }
        return base.request(method, params);
      },
    };

    await emergencyRevoke({
      callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
      bundlerRpc: spyRpc,
      chainId: CHAIN_ID,
      accountAddress: ACCOUNT,
      signingValidatorAddress: SIGNING_VALIDATOR,
      sign: fakeSign,
      ...FEE_DEPS,
      maxReceiptAttempts: 1,
      receiptPollIntervalMs: 0,
    });

    expect(typeof estimatedSignature).toBe('string');
    expect(estimatedSignature).not.toBe('0x');
    // 署名者アドレスを含む ABI エンコード（実署名と同形）。
    expect((estimatedSignature as string).toLowerCase()).toContain(
      SIGNING_VALIDATOR.slice(2).toLowerCase(),
    );
  });

  test('署名に使う Validator が install されていない場合は 1022', async () => {
    await expect(
      emergencyRevoke({
        callSource: fakeCallSource([OTHER_VALIDATOR]),
        bundlerRpc: fakeBundlerRpc(true),
        chainId: CHAIN_ID,
        accountAddress: ACCOUNT,
        signingValidatorAddress: SIGNING_VALIDATOR,
        sign: fakeSign,
        ...FEE_DEPS,
      }),
    ).rejects.toMatchObject({ code: '1022' });
  });

  test('レシートが success:false の場合は 1021', async () => {
    await expect(
      emergencyRevoke({
        callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
        bundlerRpc: fakeBundlerRpc(false),
        chainId: CHAIN_ID,
        accountAddress: ACCOUNT,
        signingValidatorAddress: SIGNING_VALIDATOR,
        sign: fakeSign,
        ...FEE_DEPS,
        maxReceiptAttempts: 1,
        receiptPollIntervalMs: 0,
      }),
    ).rejects.toMatchObject({ code: '1021' });
  });

  test('レシートが確定しないまま最大試行回数に達した場合は 1021', async () => {
    await expect(
      emergencyRevoke({
        callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
        bundlerRpc: fakeBundlerRpc(null),
        chainId: CHAIN_ID,
        accountAddress: ACCOUNT,
        signingValidatorAddress: SIGNING_VALIDATOR,
        sign: fakeSign,
        ...FEE_DEPS,
        maxReceiptAttempts: 1,
        receiptPollIntervalMs: 0,
      }),
    ).rejects.toBeInstanceOf(VericertsError);
  });

  test('署名者のみが install 済みの場合は、空の UserOperation を送らず 1022 で落とす', async () => {
    // 空の executeBatch を送っても何も削除されないのにガスは払い、レシートは success で返るため
    // 呼び出し側には「失効した」と見えてしまう。送信自体が起きないことまで固定する。
    let sent = false;
    const bundlerRpc = fakeBundlerRpc(true, () => {
      sent = true;
    });
    const promise = emergencyRevoke({
      callSource: fakeCallSource([SIGNING_VALIDATOR]),
      bundlerRpc,
      chainId: CHAIN_ID,
      accountAddress: ACCOUNT,
      signingValidatorAddress: SIGNING_VALIDATOR,
      sign: fakeSign,
      ...FEE_DEPS,
      maxReceiptAttempts: 1,
      receiptPollIntervalMs: 0,
    });
    await expect(promise).rejects.toThrow(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: '1022' });
    expect(sent).toBe(false);
  });

  test('Bundler が別の userOpHash を返したら、レシートを引かずに 1021 で落とす', async () => {
    // 返されたハッシュでそのままレシートを引くと、無関係な UserOperation のレシートを見て
    // 「失効成功」を返し得る。緊急失効ではこれが最も避けたい失敗モード。
    const promise = emergencyRevoke({
      callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
      bundlerRpc: fakeBundlerRpc(true, undefined, `0x${'cd'.repeat(32)}` as Hex),
      chainId: CHAIN_ID,
      accountAddress: ACCOUNT,
      signingValidatorAddress: SIGNING_VALIDATOR,
      sign: fakeSign,
      ...FEE_DEPS,
      maxReceiptAttempts: 1,
      receiptPollIntervalMs: 0,
    });
    await expect(promise).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'userop_hash_mismatch' },
    });
  });

  test('別の userOpHash の成功レシートでは失効成功を返さず 1021 で落とす', async () => {
    // 送信直後の hash 照合を通っても、Bundler が別 UserOperation の成功レシートを返せば
    // 「失効していないのに成功」になる。レシート側の userOpHash も要求 hash と突合する。
    const promise = emergencyRevoke({
      callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
      bundlerRpc: fakeBundlerRpc(true, undefined, undefined, `0x${'ef'.repeat(32)}` as Hex),
      chainId: CHAIN_ID,
      accountAddress: ACCOUNT,
      signingValidatorAddress: SIGNING_VALIDATOR,
      sign: fakeSign,
      ...FEE_DEPS,
      maxReceiptAttempts: 1,
      receiptPollIntervalMs: 0,
    });
    await expect(promise).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'receipt_userop_hash_mismatch' },
    });
  });
});
