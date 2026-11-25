/**
 * `rlp.ts`（RLP エンコーダ）の単体テスト。既知の RLP エンコード例（Wikipedia / go-ethereum の
 * テストベクタとして広く引用される値）で往復を確認する。
 */

import { describe, expect, test } from 'bun:test';
import { bigIntToMinimalBytes, MAX_RLP_INTEGER, rlpEncode, stripLeadingZeros } from '../rlp.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('rlpEncode', () => {
  test('空バイト列は 0x80', () => {
    expect(toHex(rlpEncode(new Uint8Array(0)))).toBe('80');
  });

  test('単一バイト < 0x80 はそのまま', () => {
    expect(toHex(rlpEncode(Uint8Array.of(0x61)))).toBe('61');
  });

  test('"dog"（3 バイト）は 0x83646f67', () => {
    expect(toHex(rlpEncode(new TextEncoder().encode('dog')))).toBe('83646f67');
  });

  test('55 バイト超の長い文字列は長さプレフィックスの長さも符号化する', () => {
    const long = new Uint8Array(56).fill(0x61);
    const encoded = rlpEncode(long);
    // prefix = 0xb7 + 1(lenOfLen) = 0xb8, 続けて長さ 56 = 0x38
    expect(encoded[0]).toBe(0xb8);
    expect(encoded[1]).toBe(56);
    expect(encoded.length).toBe(2 + 56);
  });

  test('空リストは 0xc0', () => {
    expect(toHex(rlpEncode([]))).toBe('c0');
  });

  test('["cat","dog"] は既知のエンコード結果と一致する', () => {
    const encoded = rlpEncode([new TextEncoder().encode('cat'), new TextEncoder().encode('dog')]);
    expect(toHex(encoded)).toBe('c88363617483646f67');
  });

  test('ネストしたリストも符号化できる', () => {
    const encoded = rlpEncode([Uint8Array.of(1), [Uint8Array.of(2), Uint8Array.of(3)]]);
    expect(toHex(encoded)).toBe('c401c20203');
  });
});

describe('bigIntToMinimalBytes', () => {
  test('0n は空配列', () => {
    expect(bigIntToMinimalBytes(0n).length).toBe(0);
  });

  test('1024n は [0x04, 0x00]', () => {
    expect(toHex(bigIntToMinimalBytes(1024n))).toBe('0400');
  });

  test('負の値は例外', () => {
    expect(() => bigIntToMinimalBytes(-1n)).toThrow();
  });
});

describe('stripLeadingZeros', () => {
  test('先頭ゼロを取り除く', () => {
    expect(toHex(stripLeadingZeros(Uint8Array.of(0, 0, 1, 2)))).toBe('0102');
  });

  test('全ゼロは空配列', () => {
    expect(stripLeadingZeros(Uint8Array.of(0, 0, 0)).length).toBe(0);
  });

  test('先頭ゼロが無ければそのまま', () => {
    expect(toHex(stripLeadingZeros(Uint8Array.of(5, 6)))).toBe('0506');
  });
});

describe('bigIntToMinimalBytes の上限', () => {
  test('2^256 − 1 は 32 バイトで受理し、2^256 は拒否する', () => {
    expect(bigIntToMinimalBytes(MAX_RLP_INTEGER).length).toBe(32);
    expect(() => bigIntToMinimalBytes(MAX_RLP_INTEGER + 1n)).toThrow();
  });

  test('52 万桁の巨大値は変換前に拒否する', () => {
    expect(() => bigIntToMinimalBytes(BigInt(`0x${'f'.repeat(520_000)}`))).toThrow();
  });

  test('奇数桁・先頭ゼロなしの最小長表現（0x1ff → 01 ff）', () => {
    expect(toHex(bigIntToMinimalBytes(0x1ffn))).toBe('01ff');
  });
});
