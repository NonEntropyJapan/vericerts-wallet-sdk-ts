/**
 * AES-256-GCM 暗号化→復号のラウンドトリップ検証。
 *
 * 複数長・空の平文、AAD あり/なしで encrypt→decrypt が元の平文に一致すること、
 * IV が暗号化ごとにランダムであること、出力長（IV 12B / 暗号文+16B タグ）、
 * 鍵長不正のエラー（1051）を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { decryptAesGcm, encryptAesGcm } from '../../encryption.js';

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

/** テスト用の固定 256bit 鍵（32 バイト）。 */
const KEY = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');

describe('encryptAesGcm / decryptAesGcm ラウンドトリップ', () => {
  for (const length of [0, 1, 16, 32, 64]) {
    it(`平文 ${length} バイト（AAD なし）が復号で一致する`, async () => {
      const plaintext = crypto.getRandomValues(new Uint8Array(length));
      const { iv, ciphertext } = await encryptAesGcm(KEY, plaintext);
      const decrypted = await decryptAesGcm(KEY, iv, ciphertext);
      expect(toHex(decrypted)).toBe(toHex(plaintext));
    });

    it(`平文 ${length} バイト（AAD あり）が復号で一致する`, async () => {
      const plaintext = crypto.getRandomValues(new Uint8Array(length));
      const aad = hexToBytes('deadbeefcafe');
      const { iv, ciphertext } = await encryptAesGcm(KEY, plaintext, aad);
      const decrypted = await decryptAesGcm(KEY, iv, ciphertext, aad);
      expect(toHex(decrypted)).toBe(toHex(plaintext));
    });
  }

  it('iv は 12 バイト、ciphertext は 平文長 + 16 バイトタグ', async () => {
    const plaintext = hexToBytes('00112233445566778899aabbccddeeff');
    const { iv, ciphertext } = await encryptAesGcm(KEY, plaintext);
    expect(iv.length).toBe(12);
    expect(ciphertext.length).toBe(plaintext.length + 16);
  });

  it('同一鍵・同一平文でも IV は毎回異なる（ランダム性）', async () => {
    const plaintext = hexToBytes('00112233445566778899aabbccddeeff');
    const a = await encryptAesGcm(KEY, plaintext);
    const b = await encryptAesGcm(KEY, plaintext);
    expect(toHex(a.iv)).not.toBe(toHex(b.iv));
    // IV が異なるため暗号文も異なる。
    expect(toHex(a.ciphertext)).not.toBe(toHex(b.ciphertext));
  });

  it('鍵長 31 バイトの encrypt は ENCRYPT_FAILED(1051)', async () => {
    const key = new Uint8Array(31);
    const promise = encryptAesGcm(key, hexToBytes('00'));
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.ENCRYPT_FAILED });
  });

  it('鍵長 33 バイトの encrypt は ENCRYPT_FAILED(1051)', async () => {
    const key = new Uint8Array(33);
    const promise = encryptAesGcm(key, hexToBytes('00'));
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.ENCRYPT_FAILED });
  });
});
