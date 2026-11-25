/**
 * `emergencyRevoke` の失効後オンチェーン状態の確認テスト。
 *
 * Bundler が実行せずに echo hash + `success: true` のレシートを返しても、Validator 状態の読み直しで
 * 失効が確認できなければ「失効成功」（`newWuaRequired: true`）を返さない。
 */

import { describe, expect, test } from 'bun:test';
import type { EvmCallSource } from '../../../asset/rpc.js';
import type { RecoverableSignature } from '../../../keymanager/signer.js';
import { emergencyRevoke } from '../../emergency-revoke.js';
import {
  ACCOUNT,
  CHAIN_ID,
  fakeBundlerRpc,
  fakeCallSource,
  MODULAR_ACCOUNT_IFACE,
  OTHER_VALIDATOR,
  SIGNING_VALIDATOR,
} from './emergency-revoke.fixtures.js';

const fakeSign = async (): Promise<RecoverableSignature> => ({
  signature: new Uint8Array(65),
  recovery: 0,
});

const isGetValidators = (data: string) =>
  MODULAR_ACCOUNT_IFACE.getFunction('getValidators')?.selector === data.slice(0, 10);

function revoke(callSource: EvmCallSource) {
  return emergencyRevoke({
    callSource,
    bundlerRpc: fakeBundlerRpc(true),
    chainId: CHAIN_ID,
    accountAddress: ACCOUNT,
    signingValidatorAddress: SIGNING_VALIDATOR,
    sign: fakeSign,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 900_000_000n,
    maxReceiptAttempts: 1,
    receiptPollIntervalMs: 0,
  });
}

describe('emergencyRevoke: 失効後の状態確認', () => {
  test('success レシートでも失効対象が install されたままなら、失効成功を返さず 1021 で落とす', async () => {
    const both = [SIGNING_VALIDATOR, OTHER_VALIDATOR];
    const promise = revoke(fakeCallSource(both, { postRevokeValidators: both }));
    await expect(promise).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'post_state_mismatch' },
    });
  });

  test('失効後に署名 Validator まで消えている状態も成功とみなさない', async () => {
    const promise = revoke(
      fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR], { postRevokeValidators: [] }),
    );
    await expect(promise).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'post_state_mismatch' },
    });
  });

  test('読み直しが 1 ブロック遅れて反映されても、再試行で失効を確認できれば成功を返す', async () => {
    const both = [SIGNING_VALIDATOR, OTHER_VALIDATOR];
    // 最初の読み出し（送信前）と、レシート直後の 1 回目の読み直しは未反映、2 回目で反映される。
    const stale = fakeCallSource(both, { postRevokeValidators: both });
    const honest = fakeCallSource(both);
    let reads = 0;
    const callSource: EvmCallSource = {
      ...honest,
      async call(request) {
        if (isGetValidators(request.data)) {
          reads += 1;
          return (reads <= 2 ? stale : honest).call(request);
        }
        return honest.call(request);
      },
    };
    const result = await revoke(callSource);
    expect(result.revokedValidators).toEqual([OTHER_VALIDATOR]);
    expect(result.newWuaRequired).toBe(true);
  });

  test('読み直し自体が失敗し続けるなら、成功を返さず 1021（post_state_unreadable）で落とす', async () => {
    const honest = fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]);
    let validatorReads = 0;
    const callSource: EvmCallSource = {
      ...honest,
      async call(request) {
        if (isGetValidators(request.data)) {
          validatorReads += 1;
          if (validatorReads > 1) {
            throw new Error('rpc down');
          }
        }
        return honest.call(request);
      },
    };
    await expect(revoke(callSource)).rejects.toMatchObject({
      code: '1021',
      context: { phase: 'post_state_unreadable' },
    });
  });
});
