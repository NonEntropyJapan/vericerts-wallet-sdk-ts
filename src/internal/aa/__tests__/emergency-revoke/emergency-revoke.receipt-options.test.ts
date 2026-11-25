/**
 * `emergencyRevoke` の `maxReceiptAttempts` / `receiptPollIntervalMs` 検証。
 *
 * NaN / 0 / 負値の試行回数だと UserOperation 送信後にレシートを 1 度も問い合わせず `receipt_timeout` を返し、
 * 失効が成立済みでも呼び出し側が再送して二重に失効を発行しうる。送信**前**に RangeError で拒否する。
 */

import { describe, expect, test } from 'bun:test';
import type { RecoverableSignature } from '../../../keymanager/signer.js';
import { emergencyRevoke } from '../../emergency-revoke.js';
import {
  ACCOUNT,
  CHAIN_ID,
  fakeBundlerRpc,
  fakeCallSource,
  OTHER_VALIDATOR,
  SIGNING_VALIDATOR,
} from './emergency-revoke.fixtures.js';

const fakeSign = async (): Promise<RecoverableSignature> => ({
  signature: new Uint8Array(65),
  recovery: 0,
});

function run(options: { maxReceiptAttempts?: number; receiptPollIntervalMs?: number }) {
  let sent = 0;
  const promise = emergencyRevoke({
    callSource: fakeCallSource([SIGNING_VALIDATOR, OTHER_VALIDATOR]),
    bundlerRpc: fakeBundlerRpc(true, () => {
      sent += 1;
    }),
    chainId: CHAIN_ID,
    accountAddress: ACCOUNT,
    signingValidatorAddress: SIGNING_VALIDATOR,
    sign: fakeSign,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 900_000_000n,
    ...options,
  });
  return { promise, sent: () => sent };
}

describe('emergencyRevoke — レシート待機オプションの検証', () => {
  test('maxReceiptAttempts が NaN / 0 / 負値 / 小数 / Infinity なら UserOperation を送らず RangeError', async () => {
    for (const maxReceiptAttempts of [
      Number.NaN,
      0,
      -1,
      1.5,
      Number.POSITIVE_INFINITY,
      '3' as unknown as number,
    ]) {
      const { promise, sent } = run({ maxReceiptAttempts, receiptPollIntervalMs: 0 });
      await expect(promise).rejects.toBeInstanceOf(RangeError);
      expect(sent()).toBe(0);
    }
  });

  test('receiptPollIntervalMs が NaN / 負値 / 巨大値なら UserOperation を送らず RangeError', async () => {
    for (const receiptPollIntervalMs of [Number.NaN, -1, Number.POSITIVE_INFINITY, 2 ** 31]) {
      const { promise, sent } = run({ maxReceiptAttempts: 1, receiptPollIntervalMs });
      await expect(promise).rejects.toBeInstanceOf(RangeError);
      expect(sent()).toBe(0);
    }
  });

  test('maxReceiptAttempts=1 / receiptPollIntervalMs=0 は受理され送信される', async () => {
    const { promise, sent } = run({ maxReceiptAttempts: 1, receiptPollIntervalMs: 0 });
    await promise;
    expect(sent()).toBe(1);
  });
});
