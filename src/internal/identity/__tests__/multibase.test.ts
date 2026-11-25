/**
 * multibase / multicodec varint 低レベルヘルパの検証。
 *
 * Multicodec varint エンコード、base58btc ラウンドトリップ、`z` プレフィックスの
 * 付与・除去、不正入力のエラー正規化を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  encodeMulticodecVarint,
  multibaseBase58Decode,
  multibaseBase58Encode,
} from '../multibase.js';

describe('encodeMulticodecVarint', () => {
  it('0xed (Ed25519) を [0xed, 0x01] にエンコードする', () => {
    expect(Array.from(encodeMulticodecVarint(0xed))).toEqual([0xed, 0x01]);
  });

  it('0xe7 (secp256k1) を [0xe7, 0x01] にエンコードする', () => {
    expect(Array.from(encodeMulticodecVarint(0xe7))).toEqual([0xe7, 0x01]);
  });

  it('0x1200 (P-256) を [0x80, 0x24] にエンコードする', () => {
    expect(Array.from(encodeMulticodecVarint(0x1200))).toEqual([0x80, 0x24]);
  });

  it('0x00 を [0x00] にエンコードする（1 バイト境界）', () => {
    expect(Array.from(encodeMulticodecVarint(0x00))).toEqual([0x00]);
  });

  it('0x7f を [0x7f] にエンコードする（1 バイト最大）', () => {
    expect(Array.from(encodeMulticodecVarint(0x7f))).toEqual([0x7f]);
  });
});

describe('multibaseBase58 encode/decode', () => {
  it('エンコード結果は z プレフィックスを持つ', () => {
    const text = multibaseBase58Encode(Uint8Array.from([0x01, 0x02, 0x03]));
    expect(text.startsWith('z')).toBe(true);
  });

  it('encode → decode のラウンドトリップで元バイト列に戻る', () => {
    const bytes = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    const text = multibaseBase58Encode(bytes);
    expect(Array.from(multibaseBase58Decode(text))).toEqual(Array.from(bytes));
  });

  it('decode は先頭の z を除去してデコードする', () => {
    // [0, 1, 2] の base58 は "1Ldp"（先頭ゼロは '1'）。z 付きで渡す。
    const bytes = Uint8Array.from([0x00, 0x01, 0x02]);
    const text = multibaseBase58Encode(bytes);
    expect(Array.from(multibaseBase58Decode(text))).toEqual([0x00, 0x01, 0x02]);
  });

  it('z 始まりでない文字列は 2001 を投げる', () => {
    expect(() => multibaseBase58Decode('xabc')).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });

  it('z のみ（本体空）は 2001 を投げる', () => {
    expect(() => multibaseBase58Decode('z')).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });

  it('z + 不正な base58 文字列は 2001 を投げる', () => {
    // '0', 'O', 'I', 'l' は base58 アルファベット外。
    expect(() => multibaseBase58Decode('z0OIl')).toThrow(
      new VericertsError(ErrorCodes.INVALID_DID),
    );
  });

  it('2001 エラーは code/category を持つ', () => {
    try {
      multibaseBase58Decode('xabc');
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('2001');
      expect((error as VericertsError).category).toBe('did');
    }
  });
});
