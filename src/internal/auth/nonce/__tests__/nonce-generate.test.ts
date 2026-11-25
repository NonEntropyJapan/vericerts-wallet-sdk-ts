/**
 * nonce の生成・フォーマット検査・定数時間比較のユニットテスト。
 *
 * 検証内容:
 * - generateNonce: CSPRNG 由来で base64url 22 文字（128bit）/ 43 文字（256bit）、毎回異なる。
 * - isWellFormedNonce / assertWellFormedNonce: 短すぎる・文字種違反・非文字列で 4013、UUIDv4 は許容。
 * - 回帰: nil UUID（エントロピー 0）と UUIDv4 以外の version / variant は 4013 で弾く。
 * - timingSafeEqualString / timingSafeEqualBytes: 一致 / 不一致 / 長さ違いの判定が正しい。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { timingSafeEqualBytes, timingSafeEqualString } from '../../../timing-safe.js';
import {
  assertWellFormedNonce,
  generateNonce,
  isWellFormedNonce,
  MIN_NONCE_ENTROPY_BITS,
  MIN_NONCE_LENGTH,
} from '../generate.js';

/** `VericertsError` の code を検査する。 */
function expectCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code as never);
    return;
  }
  throw new Error('例外が送出されなかった');
}

describe('generateNonce', () => {
  it('既定（16 byte = 128 bit）で base64url 22 文字を返す', () => {
    const nonce = generateNonce();
    expect(nonce).toHaveLength(MIN_NONCE_LENGTH);
    expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(MIN_NONCE_ENTROPY_BITS).toBe(128);
  });

  it('32 byte 指定で base64url 43 文字を返す', () => {
    expect(generateNonce(32)).toHaveLength(43);
  });

  it('生成した nonce は毎回異なる（CSPRNG 由来）', () => {
    const generated = new Set(Array.from({ length: 64 }, () => generateNonce()));
    expect(generated.size).toBe(64);
  });

  it('生成した nonce は自身のフォーマット検査を通る', () => {
    for (const byteLength of [16, 32] as const) {
      expect(isWellFormedNonce(generateNonce(byteLength))).toBe(true);
    }
  });
});

describe('isWellFormedNonce', () => {
  it('base64url 22 文字以上を受理する', () => {
    expect(isWellFormedNonce('AQIDBAUGBwgJCgsMDQ4PEA')).toBe(true);
    expect(isWellFormedNonce('AQIDBAUGBwgJCgsMDQ4PEA_-')).toBe(true);
  });

  it('UUIDv4 形式を受理する', () => {
    expect(isWellFormedNonce('f81d4fae-7dec-41d0-a765-00a0c91e6bf6')).toBe(true);
    expect(isWellFormedNonce('F81D4FAE-7DEC-41D0-B765-00A0C91E6BF6')).toBe(true);
  });

  it('variant nibble は 8|9|a|b のいずれも受理する（RFC 4122 §4.1.1）', () => {
    for (const variant of ['8', '9', 'a', 'b']) {
      expect(isWellFormedNonce(`f81d4fae-7dec-41d0-${variant}765-00a0c91e6bf6`)).toBe(true);
    }
  });

  it('nil UUID を拒否する（エントロピー 0）', () => {
    expect(isWellFormedNonce('00000000-0000-0000-0000-000000000000')).toBe(false);
  });

  it('UUIDv4 以外の version を拒否する（v1 はタイムスタンプ + MAC 由来）', () => {
    // v1（時刻ベース）・v3（MD5）・v5（SHA-1）・v7（Unix 時刻ベース）はいずれも不可。
    expect(isWellFormedNonce('f81d4fae-7dec-11d0-a765-00a0c91e6bf6')).toBe(false);
    expect(isWellFormedNonce('f81d4fae-7dec-31d0-a765-00a0c91e6bf6')).toBe(false);
    expect(isWellFormedNonce('f81d4fae-7dec-51d0-a765-00a0c91e6bf6')).toBe(false);
    expect(isWellFormedNonce('f81d4fae-7dec-71d0-a765-00a0c91e6bf6')).toBe(false);
  });

  it('variant nibble が RFC 4122 の 8|9|a|b でなければ拒否する', () => {
    for (const variant of ['0', '1', '7', 'c', 'd', 'e', 'f']) {
      expect(isWellFormedNonce(`f81d4fae-7dec-41d0-${variant}765-00a0c91e6bf6`)).toBe(false);
    }
  });

  it('22 文字未満はエントロピー不足として拒否する', () => {
    expect(isWellFormedNonce('AQIDBAUGBwgJCgsMDQ4PE')).toBe(false);
    expect(isWellFormedNonce('verifier-nonce-1')).toBe(false);
  });

  it('base64url 以外の文字種を拒否する', () => {
    expect(isWellFormedNonce('AQIDBAUGBwgJCgsMDQ4PE!')).toBe(false);
    expect(isWellFormedNonce('AQIDBAUGBwgJCgsMDQ4PE+')).toBe(false);
    expect(isWellFormedNonce('AQIDBAUGBwgJCgsMDQ4PE=')).toBe(false);
  });

  it('空文字・非文字列を拒否する', () => {
    expect(isWellFormedNonce('')).toBe(false);
    expect(isWellFormedNonce(undefined)).toBe(false);
    expect(isWellFormedNonce(null)).toBe(false);
    expect(isWellFormedNonce(12_345_678_901_234_567_890_123n)).toBe(false);
  });
});

describe('assertWellFormedNonce', () => {
  it('不正なフォーマットで 4013 NONCE_MALFORMED を投げる', () => {
    expectCode(() => assertWellFormedNonce('short'), ErrorCodes.NONCE_MALFORMED);
    expectCode(() => assertWellFormedNonce(''), ErrorCodes.NONCE_MALFORMED);
    expectCode(() => assertWellFormedNonce(42), ErrorCodes.NONCE_MALFORMED);
  });

  it('nil UUID と UUIDv1 を 4013 で弾く（エントロピー不足 / タイムスタンプ由来）', () => {
    expectCode(
      () => assertWellFormedNonce('00000000-0000-0000-0000-000000000000'),
      ErrorCodes.NONCE_MALFORMED,
    );
    expectCode(
      () => assertWellFormedNonce('f81d4fae-7dec-11d0-a765-00a0c91e6bf6'),
      ErrorCodes.NONCE_MALFORMED,
    );
  });

  it('正当な nonce では例外を投げない', () => {
    expect(() => assertWellFormedNonce(generateNonce())).not.toThrow();
    expect(() => assertWellFormedNonce(crypto.randomUUID())).not.toThrow();
  });
});

describe('timingSafeEqualString / timingSafeEqualBytes', () => {
  it('同一文字列で true を返す', () => {
    expect(timingSafeEqualString('client-id-abc', 'client-id-abc')).toBe(true);
    expect(timingSafeEqualString('', '')).toBe(true);
  });

  it('内容が異なれば false を返す', () => {
    expect(timingSafeEqualString('client-id-abc', 'client-id-abd')).toBe(false);
  });

  it('長さが異なれば false を返す（早期 return せず判定できる）', () => {
    expect(timingSafeEqualString('abc', 'abcd')).toBe(false);
    expect(timingSafeEqualString('abcd', 'abc')).toBe(false);
    expect(timingSafeEqualString('', 'a')).toBe(false);
  });

  it('マルチバイト文字を UTF-8 バイト列として比較する', () => {
    expect(timingSafeEqualString('検証者', '検証者')).toBe(true);
    expect(timingSafeEqualString('検証者', '検証省')).toBe(false);
  });

  it('バイト列比較でも同じ判定になる', () => {
    expect(timingSafeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(timingSafeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(timingSafeEqualBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0]))).toBe(false);
  });
});
