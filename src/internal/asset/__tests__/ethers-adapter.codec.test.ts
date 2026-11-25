/**
 * ethers-adapter.ts（asset 既定 seam 実装、残高取得 / 送金 Tx / NFT 一覧取得）の
 * ABI codec 統合テスト。
 *
 * 実 ethers を用いて以下を検証する:
 * - `createErc20AbiCodec`: read 系（balanceOf / decimals / symbol）の encode/decode と
 *   `transfer` calldata が正しいセレクタ・引数でエンコードされる。
 * - `createErc721AbiCodec` / `createErc1155AbiCodec`: NFT read ABI（balanceOf / ownerOf /
 *   tokenURI / balanceOfBatch / uri）の encode/decode が正しいセレクタ・戻り値で処理される。
 */

import { describe, expect, test } from 'bun:test';
import { AbiCoder, Interface } from 'ethers';
import { ErrorCodes } from '../../errors.js';
import {
  createErc20AbiCodec,
  createErc721AbiCodec,
  createErc1155AbiCodec,
} from '../ethers-adapter.js';

const TO = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const HOLDER = '0x1111111111111111111111111111111111111111';

describe('createErc20AbiCodec（read encode/decode）', () => {
  test('balanceOf を ethers と同一の calldata にエンコードする', () => {
    const codec = createErc20AbiCodec();
    const iface = new Interface(['function balanceOf(address owner) view returns (uint256)']);
    expect(codec.encode('balanceOf', [HOLDER])).toBe(
      iface.encodeFunctionData('balanceOf', [HOLDER]),
    );
  });

  test('uint256 戻り値を bigint にデコードできる（round-trip）', () => {
    const codec = createErc20AbiCodec();
    const iface = new Interface(['function balanceOf(address owner) view returns (uint256)']);
    const raw = iface.encodeFunctionResult('balanceOf', [123456789n]);
    expect(codec.decode('balanceOf', raw)[0]).toBe(123456789n);
  });

  test('decimals / symbol をデコードできる', () => {
    const codec = createErc20AbiCodec();
    const iface = new Interface([
      'function decimals() view returns (uint8)',
      'function symbol() view returns (string)',
    ]);
    expect(codec.decode('decimals', iface.encodeFunctionResult('decimals', [18]))[0]).toBe(18n);
    expect(codec.decode('symbol', iface.encodeFunctionResult('symbol', ['USDC']))[0]).toBe('USDC');
  });

  test('不正アドレス引数のエンコードは 4070 に正規化する', () => {
    const codec = createErc20AbiCodec();
    expect(() => codec.encode('balanceOf', ['not-an-address'])).toThrow();
    try {
      codec.encode('balanceOf', ['not-an-address']);
    } catch (error) {
      expect((error as { code?: string }).code).toBe(ErrorCodes.INVALID_EVM_ADDRESS);
    }
  });

  test('デコード不能な戻り値は 1021 に正規化する', () => {
    const codec = createErc20AbiCodec();
    try {
      codec.decode('balanceOf', '0x');
      throw new Error('should have thrown');
    } catch (error) {
      expect((error as { code?: string }).code).toBe(ErrorCodes.CHAIN_SUBMIT_FAILED);
    }
  });
});

describe('createErc20AbiCodec（transfer encode）', () => {
  test('transfer(to, amount) を正しいセレクタでエンコードする', () => {
    const codec = createErc20AbiCodec();
    const data = codec.encode('transfer', [TO, 1000n]);
    // ERC-20 transfer(address,uint256) のセレクタは 0xa9059cbb。
    expect(data.startsWith('0xa9059cbb')).toBe(true);
    // 受取人アドレス（小文字・32 バイト右詰め）が calldata に含まれる。
    expect(data.toLowerCase()).toContain(TO.slice(2).toLowerCase());
  });

  test('不正なアドレス引数は INVALID_EVM_ADDRESS（4070）に正規化する', () => {
    const codec = createErc20AbiCodec();
    expect(() => codec.encode('transfer', ['0xnotanaddress', 1n])).toThrow();
    try {
      codec.encode('transfer', ['0xnotanaddress', 1n]);
    } catch (e) {
      expect((e as { code: string }).code).toBe(ErrorCodes.INVALID_EVM_ADDRESS);
    }
  });
});

describe('createErc721AbiCodec', () => {
  test('balanceOf / ownerOf / tokenURI の calldata は正しいセレクタ', () => {
    const codec = createErc721AbiCodec();
    // balanceOf(address) のセレクタは 0x70a08231。
    expect(codec.encode('balanceOf', [HOLDER]).slice(0, 10)).toBe('0x70a08231');
    // ownerOf(uint256) のセレクタは 0x6352211e。
    expect(codec.encode('ownerOf', [1n]).slice(0, 10)).toBe('0x6352211e');
    // tokenURI(uint256) のセレクタは 0xc87b56dd。
    expect(codec.encode('tokenURI', [1n]).slice(0, 10)).toBe('0xc87b56dd');
  });

  test('balanceOf の uint256 戻り値をデコードできる', () => {
    const codec = createErc721AbiCodec();
    const encoded = AbiCoder.defaultAbiCoder().encode(['uint256'], [123456789n]);
    const [value] = codec.decode('balanceOf', encoded);
    expect(value).toBe(123456789n);
  });

  test('ownerOf の address 戻り値をデコードできる', () => {
    const codec = createErc721AbiCodec();
    const encoded = AbiCoder.defaultAbiCoder().encode(['address'], [HOLDER]);
    const [value] = codec.decode('ownerOf', encoded);
    expect((value as string).toLowerCase()).toBe(HOLDER.toLowerCase());
  });

  test('tokenURI の string 戻り値をデコードできる', () => {
    const codec = createErc721AbiCodec();
    const encoded = AbiCoder.defaultAbiCoder().encode(['string'], ['ipfs://x/1']);
    const [value] = codec.decode('tokenURI', encoded);
    expect(value).toBe('ipfs://x/1');
  });

  test('引数不正は 4070 に正規化（cause を露出しない）', () => {
    const codec = createErc721AbiCodec();
    try {
      codec.encode('ownerOf', ['not-a-uint']);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('4070');
      expect((e as Error).cause).toBeUndefined();
    }
  });

  test('デコード不能（不正な戻り値）は 1021 に正規化', () => {
    const codec = createErc721AbiCodec();
    try {
      codec.decode('balanceOf', '0x');
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1021');
    }
  });
});

describe('createErc1155AbiCodec', () => {
  test('balanceOf(address,uint256) / balanceOfBatch / uri のセレクタ', () => {
    const codec = createErc1155AbiCodec();
    // balanceOf(address,uint256) のセレクタは 0x00fdd58e。
    expect(codec.encode('balanceOf', [HOLDER, 1n]).slice(0, 10)).toBe('0x00fdd58e');
    // balanceOfBatch(address[],uint256[]) のセレクタは 0x4e1273f4。
    expect(codec.encode('balanceOfBatch', [[HOLDER], [1n]]).slice(0, 10)).toBe('0x4e1273f4');
    // uri(uint256) のセレクタは 0x0e89341c。
    expect(codec.encode('uri', [1n]).slice(0, 10)).toBe('0x0e89341c');
  });

  test('balanceOfBatch の uint256[] 戻り値をデコードできる', () => {
    const codec = createErc1155AbiCodec();
    const encoded = AbiCoder.defaultAbiCoder().encode(['uint256[]'], [[1n, 2n, 3n]]);
    const [value] = codec.decode('balanceOfBatch', encoded);
    expect((value as readonly bigint[]).map((v) => BigInt(v))).toEqual([1n, 2n, 3n]);
  });

  test('引数不正は 4070 に正規化（cause を露出しない）', () => {
    const codec = createErc1155AbiCodec();
    try {
      codec.encode('balanceOf', ['not-an-address', 1n]);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('4070');
      expect((e as Error).cause).toBeUndefined();
    }
  });
});
