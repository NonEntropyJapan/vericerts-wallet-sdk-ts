/**
 * HD 導出関数の振る舞い検証。
 *
 * hardened / non-hardened の差異、鍵素材のバイト長、決定性、不正パスのエラー、
 * 秘密情報の非漏洩、および基本的な性能要件を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { deriveKeyFromSeed, deriveMasterKey, mnemonicToSeed } from '../../hd.js';

/** hex 文字列をバイト列へ変換する（テスト専用ヘルパ）。 */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** バイト列を hex 文字列へ変換する（テスト専用ヘルパ）。 */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// BIP-32 test vector 1 のシード。テスト全体で共有する。
const SEED = hexToBytes('000102030405060708090a0b0c0d0e0f');

describe('deriveMasterKey', () => {
  it('derives the master key at path m', () => {
    const master = deriveMasterKey(SEED);
    expect(master.derivationPath).toBe('m');
    expect(master.privateKey.length).toBe(32);
    expect(master.publicKey.length).toBe(33);
    expect(master.chainCode.length).toBe(32);
  });
});

describe('deriveKeyFromSeed', () => {
  it('returns different private keys for hardened vs non-hardened paths', () => {
    const hardened = deriveKeyFromSeed(SEED, "m/44'/60'/0'");
    const nonHardened = deriveKeyFromSeed(SEED, 'm/44/60/0');
    expect(toHex(hardened.privateKey)).not.toBe(toHex(nonHardened.privateKey));
  });

  it('produces key material with the expected byte lengths', () => {
    const key = deriveKeyFromSeed(SEED, "m/44'/60'/0'/0/0");
    expect(key.privateKey.length).toBe(32);
    expect(key.publicKey.length).toBe(33);
    expect(key.chainCode.length).toBe(32);
    expect(key.derivationPath).toBe("m/44'/60'/0'/0/0");
  });

  it('is deterministic for the same seed and path', () => {
    const first = deriveKeyFromSeed(SEED, "m/44'/60'/0'/0/0");
    const second = deriveKeyFromSeed(SEED, "m/44'/60'/0'/0/0");
    expect(first).toEqual(second);
  });

  it.each([
    '',
    'foo',
    "m/44'/60'/x",
    '/44/60',
  ])('throws DERIVATION_PATH_INVALID (code 1040) for invalid path %p', (path) => {
    let caught: unknown;
    try {
      deriveKeyFromSeed(SEED, path);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
  });

  it('does not leak seed or private key in error messages', () => {
    const seedHex = toHex(SEED);
    let thrown: unknown;
    try {
      deriveKeyFromSeed(SEED, 'not-a-path');
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    const message = (thrown as VericertsError).message;
    // 秘密を含まない静的な日本語メッセージ。
    expect(message).toBe('不正な BIP-44 導出パスです');
    expect(message).not.toContain(seedHex);
    // 派生に成功するパスの秘密鍵 hex も漏れていないことを確認する。
    const privateKeyHex = toHex(deriveKeyFromSeed(SEED, "m/44'/60'/0'/0/0").privateKey);
    expect(message).not.toContain(privateKeyHex);
  });

  it("derives m/44'/60'/0'/0/0 within the performance budget (<50ms)", () => {
    // non-functional 性能要件。CI のフレーク耐性のため 50ms の余裕マージンを設ける
    // （単一 secp256k1 派生は通常 1ms 未満で完了する）。
    const start = performance.now();
    deriveKeyFromSeed(SEED, "m/44'/60'/0'/0/0");
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(50);
  });
});

describe('mnemonicToSeed', () => {
  it('produces a 64-byte (512-bit) seed', () => {
    const mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const seed = mnemonicToSeed(mnemonic);
    expect(seed.length).toBe(64);
  });

  it('throws INVALID_MNEMONIC (code 1001) for an invalid mnemonic', () => {
    let caught: unknown;
    try {
      mnemonicToSeed('not a valid mnemonic phrase at all here');
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_MNEMONIC);
  });
});
