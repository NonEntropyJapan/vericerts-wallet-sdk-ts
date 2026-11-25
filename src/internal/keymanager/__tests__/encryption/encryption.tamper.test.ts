/**
 * AES-256-GCM 改ざん検出・パラメータ前提違反の検証。
 *
 * 暗号文 / タグ / IV / AAD の改ざんが復号失敗（1050）として検出されること、
 * 一方で鍵長・IV 長の前提違反は復号タグ失敗（1050）ではなく暗号化失敗（1051）として
 * 区別されることを確認する。
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

/** 指定インデックスのバイトを反転した複製を返す（テスト専用ヘルパ）。 */
function withFlippedByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = Uint8Array.from(bytes);
  copy.set([(copy[index] ?? 0) ^ 0xff], index);
  return copy;
}

/** テスト用の固定 256bit 鍵（32 バイト）。 */
const KEY = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
/** テスト用の平文（16 バイト）。 */
const PLAINTEXT = hexToBytes('00112233445566778899aabbccddeeff');

describe('decryptAesGcm 改ざん検出', () => {
  it('暗号文 1 バイト反転で DECRYPT_FAILED(1050)', async () => {
    const { iv, ciphertext } = await encryptAesGcm(KEY, PLAINTEXT);
    // 先頭（暗号文部）の 1 バイトを反転。
    const tampered = withFlippedByte(ciphertext, 0);
    const promise = decryptAesGcm(KEY, iv, tampered);
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.DECRYPT_FAILED });
  });

  it('タグ部の改ざんで DECRYPT_FAILED(1050)', async () => {
    const { iv, ciphertext } = await encryptAesGcm(KEY, PLAINTEXT);
    // 末尾 16 バイトの GCM タグ部の最終バイトを反転。
    const tampered = withFlippedByte(ciphertext, ciphertext.length - 1);
    const promise = decryptAesGcm(KEY, iv, tampered);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.DECRYPT_FAILED });
  });

  it('IV 改ざんで DECRYPT_FAILED(1050)', async () => {
    const { iv, ciphertext } = await encryptAesGcm(KEY, PLAINTEXT);
    const tampered = withFlippedByte(iv, 0);
    const promise = decryptAesGcm(KEY, tampered, ciphertext);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.DECRYPT_FAILED });
  });

  it('AAD あり暗号化を別 AAD で復号すると DECRYPT_FAILED(1050)', async () => {
    const aad = hexToBytes('deadbeef');
    const { iv, ciphertext } = await encryptAesGcm(KEY, PLAINTEXT, aad);
    const promise = decryptAesGcm(KEY, iv, ciphertext, hexToBytes('cafebabe'));
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.DECRYPT_FAILED });
  });

  it('AAD あり暗号化を AAD なしで復号すると DECRYPT_FAILED(1050)', async () => {
    const aad = hexToBytes('deadbeef');
    const { iv, ciphertext } = await encryptAesGcm(KEY, PLAINTEXT, aad);
    const promise = decryptAesGcm(KEY, iv, ciphertext);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.DECRYPT_FAILED });
  });

  it('鍵長 31 バイトの decrypt は ENCRYPT_FAILED(1051)（前提違反は 1050 でない）', async () => {
    const { iv, ciphertext } = await encryptAesGcm(KEY, PLAINTEXT);
    const promise = decryptAesGcm(new Uint8Array(31), iv, ciphertext);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.ENCRYPT_FAILED });
  });

  it('鍵長 33 バイトの decrypt は ENCRYPT_FAILED(1051)', async () => {
    const { iv, ciphertext } = await encryptAesGcm(KEY, PLAINTEXT);
    const promise = decryptAesGcm(new Uint8Array(33), iv, ciphertext);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.ENCRYPT_FAILED });
  });

  it('IV 長 11 バイトの decrypt は ENCRYPT_FAILED(1051)', async () => {
    const { ciphertext } = await encryptAesGcm(KEY, PLAINTEXT);
    const promise = decryptAesGcm(KEY, new Uint8Array(11), ciphertext);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.ENCRYPT_FAILED });
  });

  it('IV 長 13 バイトの decrypt は ENCRYPT_FAILED(1051)', async () => {
    const { ciphertext } = await encryptAesGcm(KEY, PLAINTEXT);
    const promise = decryptAesGcm(KEY, new Uint8Array(13), ciphertext);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.ENCRYPT_FAILED });
  });
});
