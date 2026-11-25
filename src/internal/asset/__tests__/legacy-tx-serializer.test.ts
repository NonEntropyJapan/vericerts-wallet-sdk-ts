/**
 * `legacy-tx-serializer.ts`（ethers 非依存 legacy `TxSerializer`）の署名・送信統合テスト。
 *
 * `ethers-adapter.tx.test.ts` と同じ検証手順（署名済み生 Tx を ethers で復元し、送信者・宛先・
 * calldata・serializeUnsigned が ethers 実装と一致することを確認）を、ethers 実装の代わりに
 * `createLegacyTxSerializer()` に対して行う。extension が実際に使う実装がこのテストで担保される。
 */

import { describe, expect, spyOn, test } from 'bun:test';
import { Transaction } from 'ethers';
import { ErrorCodes } from '../../errors.js';
import { KeyManager } from '../../keymanager/keymanager.js';
import { signAndSendTransaction, type TransactionRequest } from '../erc20-tx.js';
import { createLegacyTxSerializer } from '../legacy-tx-serializer.js';
import { MAX_RLP_INTEGER } from '../rlp.js';
import type { EvmCallRequest, EvmCallSource, EvmSendRequest } from '../rpc.js';

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
// BIP-39 既知テストニーモニック（テスト専用、Anvil/Hardhat 既定）。
const TEST_MNEMONIC = 'test test test test test test test test test test test junk';
const ETH_PATH = "m/44'/60'/0'/0/0";

describe('createLegacyTxSerializer + keymanager Signer（署名・送信統合）', () => {
  test('署名済み生 Tx から復元した送信者が Signer のアドレスと一致する', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const signer = km.getSigner(keyPair.id);

    const serializer = createLegacyTxSerializer();
    const data = '0xa9059cbb';
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data,
      gasLimit: 65000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };

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

    const parsed = Transaction.from(raw);
    expect(parsed.from?.toLowerCase()).toBe(signer.address().toLowerCase());
    expect(parsed.to?.toLowerCase()).toBe(TOKEN.toLowerCase());
    expect(parsed.data).toBe(data);
    expect(parsed.value).toBe(0n);
    expect(parsed.nonce).toBe(0);
    expect(parsed.gasLimit).toBe(65000n);
    expect(parsed.chainId).toBe(1n);
    expect(parsed.type).toBe(0);
  });

  test('serializeUnsigned は ethers の unsignedSerialized と一致する', () => {
    const serializer = createLegacyTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 123456789n,
      data: '0xa9059cbb',
      gasLimit: 21000n,
      gasPrice: 1_000_000_000n,
      nonce: 3,
      chainId: 137,
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

  test('0x プレフィックス無しの to（宛先アドレス）は 1021 で拒否する', () => {
    const serializer = createLegacyTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN.slice(2),
      value: 0n,
      data: '0xa9059cbb',
      gasLimit: 21000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };
    try {
      serializer.serializeUnsigned(tx);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1021');
    }
  });

  test('0x プレフィックス無しの data（calldata）は 1021 で拒否する', () => {
    const serializer = createLegacyTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data: 'a9059cbb',
      gasLimit: 21000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };
    try {
      serializer.serializeUnsigned(tx);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1021');
    }
  });

  test('nonce=0・value=0 など空バイト列に落ちるフィールドも ethers と一致する', () => {
    const serializer = createLegacyTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data: '0x',
      gasLimit: 21000n,
      gasPrice: 0n,
      nonce: 0,
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
    expect(`0x${Buffer.from(bytes).toString('hex')}`).toBe(expected);
  });

  test('署名長が 65 バイトでない場合は 1021 に正規化する', () => {
    const serializer = createLegacyTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data: '0xa9059cbb',
      gasLimit: 21000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };
    try {
      serializer.assembleSigned(tx, new Uint8Array(64));
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1021');
    }
  });

  test('recovery（末尾バイト）が 0/1 以外の場合は 1021 に正規化する', () => {
    const serializer = createLegacyTxSerializer();
    const tx: TransactionRequest = {
      to: TOKEN,
      value: 0n,
      data: '0xa9059cbb',
      gasLimit: 21000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };
    const badSig = new Uint8Array(65).fill(0x11);
    badSig[64] = 2;
    try {
      serializer.assembleSigned(tx, badSig);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1021');
    }
  });

  test('チェーン ID の大きい値（EIP-155 v の 2 バイト超え）でも往復できる', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const signer = km.getSigner(keyPair.id);
    const serializer = createLegacyTxSerializer();
    const tx: TransactionRequest = {
      to: TO,
      value: 1_000_000_000_000_000_000n,
      data: '0x',
      gasLimit: 21000n,
      gasPrice: 2_000_000_000n,
      nonce: 42,
      chainId: 42161,
    };
    const unsigned = serializer.serializeUnsigned(tx);
    const signature = await signer.sign(unsigned);
    const raw = serializer.assembleSigned(tx, signature);
    const parsed = Transaction.from(raw);
    expect(parsed.from?.toLowerCase()).toBe(signer.address().toLowerCase());
    expect(parsed.chainId).toBe(42161n);
    expect(parsed.value).toBe(tx.value);
    expect(parsed.nonce).toBe(42);
  });

  // `to = ''`（contract creation）は ERC-20 transfer 専用の TransactionRequest では表現しない。
  test.each(['', '0x', '0x12', 'garbage'])('to=%p は署名対象にせず 1021 で拒否する', (to) => {
    const serializer = createLegacyTxSerializer();
    const tx: TransactionRequest = {
      to,
      value: 0n,
      data: '0xa9059cbb',
      gasLimit: 65000n,
      gasPrice: 1_000_000_000n,
      nonce: 0,
      chainId: 1,
    };
    expect(() => serializer.serializeUnsigned(tx)).toThrow(
      expect.objectContaining({ code: ErrorCodes.CHAIN_SUBMIT_FAILED }),
    );
  });
});

describe('createLegacyTxSerializer: 桁数無制限の数量の拒否', () => {
  const base: TransactionRequest = {
    to: TO,
    value: 0n,
    data: '0x',
    gasLimit: 21000n,
    gasPrice: 1n,
    nonce: 0,
    chainId: 1,
  };

  // ランタイムの BigInt 長上限に依存しないよう、巨大な BigInt はテスト側で構築しない（古い Bun では
  // `BigInt('0x' + 'f'.repeat(520_000))` の構築自体が 'BigInt generated from this operation is too big' で
  // 落ちる）。上限検査が 16 進文字列化（桁数に比例するコスト）より前に働くことを、`toString` を呼ばせずに pin する。
  test.each([
    'gasLimit',
    'value',
    'gasPrice',
  ] as const)('%s が uint256 を超えると serializeUnsigned は例外で、16 進文字列化に進まない', (field) => {
    for (const bits of [257n, 1_024n, 16_384n]) {
      const tx = { ...base, [field]: 1n << bits };
      const original = BigInt.prototype.toString;
      let oversizedHexConversions = 0;
      const hexSpy = spyOn(BigInt.prototype, 'toString').mockImplementation(function (
        this: bigint,
        radix?: number,
      ) {
        if (radix === 16 && this > MAX_RLP_INTEGER) {
          oversizedHexConversions += 1;
        }
        return original.call(this, radix);
      });
      try {
        expect(() => createLegacyTxSerializer().serializeUnsigned(tx)).toThrow(
          expect.objectContaining({ code: ErrorCodes.CHAIN_SUBMIT_FAILED }),
        );
        expect(oversizedHexConversions).toBe(0);
      } finally {
        hexSpy.mockRestore();
      }
    }
  });

  test.each([
    'gasLimit',
    'value',
    'gasPrice',
  ] as const)('%s が 2^256 ちょうどで拒否され、2^256 − 1 は受理される（境界）', (field) => {
    const serializer = createLegacyTxSerializer();
    expect(() => serializer.serializeUnsigned({ ...base, [field]: 1n << 256n })).toThrow();
    expect(
      serializer.serializeUnsigned({ ...base, [field]: (1n << 256n) - 1n }).length,
    ).toBeGreaterThan(32);
  });

  test('uint256 最大の value は直列化できる', () => {
    const tx = { ...base, value: (1n << 256n) - 1n };
    expect(createLegacyTxSerializer().serializeUnsigned(tx).length).toBeGreaterThan(32);
  });
});
