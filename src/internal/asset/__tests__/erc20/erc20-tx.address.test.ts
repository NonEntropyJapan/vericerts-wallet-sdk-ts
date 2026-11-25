/**
 * `buildTransferTx` のアドレス検証。
 *
 * `tokenAddress` / `from` を検証しないと、`tokenAddress = ''` が `to = null` のコントラクト作成 Tx
 * として署名・送信できていた。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { buildTransferTx } from '../../erc20-tx.js';
import { fakeCallSource, fakeCodec } from './erc20-tx.fakes.js';

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const FROM = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

describe('buildTransferTx のアドレス検証', () => {
  test.each([
    ['tokenAddress が空文字', FROM, ''],
    ['tokenAddress が短い', FROM, '0x12'],
    ['tokenAddress が undefined', FROM, undefined],
    ['from が空文字', '', TOKEN],
    ['from が不正', 'garbage', TOKEN],
  ])('%s は RPC・codec に到達せず 4070', async (_name, from, tokenAddress) => {
    const { codec, calls } = fakeCodec();
    const { callSource, fetched } = fakeCallSource();
    await expect(
      buildTransferTx(1, from, TO, 1n, tokenAddress as string, { codec, callSource }),
    ).rejects.toMatchObject({ code: ErrorCodes.INVALID_EVM_ADDRESS });
    expect(calls).toHaveLength(0);
    expect(fetched).toHaveLength(0);
  });

  test('正しいアドレスなら従来どおり Tx を返す', async () => {
    const { codec } = fakeCodec();
    const { callSource } = fakeCallSource();
    const tx = await buildTransferTx(1, FROM, TO, 1n, TOKEN, { codec, callSource });
    expect(tx.to).toBe(TOKEN);
  });
});
