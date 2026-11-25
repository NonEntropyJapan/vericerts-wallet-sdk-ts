/**
 * ethers-adapter.ts（asset 既定 seam 実装、送金 Tx / read 経路）の
 * Tx シリアライザ・Signer 統合および call source 統合テスト。
 *
 * 実 ethers を用いて以下を検証する:
 * - `createTxSerializer` + keymanager `Signer`: 未署名 Tx の署名対象が EVM 署名ハッシュと一致し、
 *   署名済み生 Tx から ethers が復元する送信者が Signer のアドレスと一致する（署名・送信の統合検証）。
 * - `createEthersCallSource` / `createEvmCallSource`: 未設定チェーンが `CHAIN_NOT_CONFIGURED`（4071）に
 *   正規化される。
 * - RPC 往復（本文・時間の上限、結果の形状検査）は `bounded-rpc/__tests__/call-source.test.ts` が検証する。
 */

import { describe, expect, test } from 'bun:test';
import { Transaction } from 'ethers';
import { ErrorCodes } from '../../errors.js';
import { KeyManager } from '../../keymanager/keymanager.js';
import { signAndSendTransaction, type TransactionRequest } from '../erc20-tx.js';
import {
  createErc20AbiCodec,
  createEthersCallSource,
  createEvmCallSource,
  createTxSerializer,
} from '../ethers-adapter.js';
import type { EvmCallRequest, EvmCallSource, EvmSendRequest } from '../rpc.js';

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const HOLDER = '0x1111111111111111111111111111111111111111';
// BIP-39 既知テストニーモニック（テスト専用、Anvil/Hardhat 既定）。
const TEST_MNEMONIC = 'test test test test test test test test test test test junk';
const ETH_PATH = "m/44'/60'/0'/0/0";

describe('createTxSerializer + keymanager Signer（署名・送信統合）', () => {
  test('署名済み生 Tx から復元した送信者が Signer のアドレスと一致する', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const signer = km.getSigner(keyPair.id);

    const serializer = createTxSerializer();
    const codec = createErc20AbiCodec();
    const data = codec.encode('transfer', [TO, 1000n]);
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data,
      gasLimit: 65000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };

    // ブロードキャストはせず、send で渡された署名済み生 Tx を捕捉する。
    let raw = '';
    const callSource: EvmCallSource = {
      async call(_request: EvmCallRequest) {
        throw new Error('not used');
      },
      async nativeBalance() {
        throw new Error('not used');
      },
      async fetchTxParams() {
        throw new Error('not used');
      },
      async send(request: EvmSendRequest) {
        raw = request.rawTransaction;
        return '0xdeadbeef';
      },
    };

    const hash = await signAndSendTransaction(tx, { signer, callSource, serializer });
    expect(hash).toBe('0xdeadbeef');

    // ethers で署名済み生 Tx を復元し、送信者・宛先・calldata を検証する。
    const parsed = Transaction.from(raw);
    expect(parsed.from?.toLowerCase()).toBe(signer.address().toLowerCase());
    expect(parsed.to?.toLowerCase()).toBe(TOKEN.toLowerCase());
    expect(parsed.data).toBe(data);
    expect(parsed.value).toBe(0n);
    expect(parsed.nonce).toBe(0);
    expect(parsed.gasLimit).toBe(65000n);
    expect(parsed.chainId).toBe(1n);
  });

  test('serializeUnsigned は EVM 署名対象（unsignedSerialized）と一致する', () => {
    const serializer = createTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data: '0xa9059cbb',
      gasLimit: 21000n,
      gasPrice: 1_000_000_000n,
      nonce: 3,
      chainId: 1,
    };
    const expected = Transaction.from({
      type: 0,
      to: tx.to,
      value: tx.value,
      data: tx.data,
      gasLimit: tx.gasLimit,
      gasPrice: tx.gasPrice,
      nonce: tx.nonce,
      chainId: tx.chainId,
    }).unsignedSerialized;
    const bytes = serializer.serializeUnsigned(tx);
    const hex = `0x${Buffer.from(bytes).toString('hex')}`;
    expect(hex).toBe(expected);
  });

  test('署名長が 65 バイトでない場合は 1021 に正規化する', () => {
    const serializer = createTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data: '0xa9059cbb',
      gasLimit: 21000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };
    expect(() => serializer.assembleSigned(tx, new Uint8Array(64))).toThrow();
    try {
      serializer.assembleSigned(tx, new Uint8Array(64));
    } catch (e) {
      expect((e as { code: string }).code).toBe('1021');
    }
  });

  test('recovery（末尾バイト）が 0/1 以外の場合は 1021 に正規化する', () => {
    const serializer = createTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data: '0xa9059cbb',
      gasLimit: 21000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };
    // 末尾バイトを 2（不正な recovery）にした 65 バイト署名。
    const badSig = new Uint8Array(65).fill(0x11);
    badSig[64] = 2;
    try {
      serializer.assembleSigned(tx, badSig);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1021');
    }
  });
});

describe('createEthersCallSource（read）', () => {
  test('未設定チェーンの call は 4071（ネットワークアクセスなし）', async () => {
    const callSource = createEthersCallSource({});
    await expect(callSource.call({ chainId: 999, to: TOKEN, data: '0x' })).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_NOT_CONFIGURED,
    });
  });

  test('未設定チェーンの nativeBalance は 4071（ネットワークアクセスなし）', async () => {
    const callSource = createEthersCallSource({ 1: 'https://example.invalid/rpc' });
    await expect(callSource.nativeBalance(42161, HOLDER)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_NOT_CONFIGURED,
    });
  });
});

describe('createEvmCallSource（送金経路）', () => {
  test('未設定チェーンは CHAIN_NOT_CONFIGURED（4071）に正規化する', async () => {
    const callSource = createEvmCallSource({ 1: 'http://localhost:8545' });
    await expect(
      callSource.fetchTxParams(999, TO, { to: TOKEN, data: '0x', value: 0n }),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_NOT_CONFIGURED });
    await expect(callSource.send({ chainId: 999, rawTransaction: '0x00' })).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_NOT_CONFIGURED,
    });
  });
});
