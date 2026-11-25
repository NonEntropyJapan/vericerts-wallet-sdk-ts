/**
 * AES-256-GCM 既知ベクター（CAVP/KAT）適合検証。
 *
 * 実在の公開ベクター（McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)",
 * Submission to NIST Modes of Operation Process, 2004 の Test Case 13–16, AES-256・IV=96bit）を
 * 用いて、`encryptAesGcmWithIv` が `CT || Tag` を再現し、`decryptAesGcm` が期待 PT を
 * 返すことの双方向適合を検証する。Web Crypto は ct||tag を扱うため期待値は `CT || Tag` を結合する。
 *
 * 出典: David A. McGrew, John Viega, "The Galois/Counter Mode of Operation (GCM)", 2004,
 *       Appendix B "AES Test Vectors", Test Case 13/14/16（NIST SP 800-38D の参照実装ベクター）。
 *
 * 注意: `encryptAesGcmWithIv` は IV を呼び出し側が固定するためテスト専用 API（index.ts では
 * re-export しない）。本番の暗号化は必ず IV をランダム生成する `encryptAesGcm` を使う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { decryptAesGcm, encryptAesGcmWithIv } from '../../encryption.js';

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

interface CavpVector {
  readonly name: string;
  readonly key: string;
  readonly iv: string;
  readonly plaintext: string;
  readonly aad?: string;
  /** 期待暗号文（ct）。 */
  readonly ciphertext: string;
  /** 期待 GCM タグ（16 バイト）。 */
  readonly tag: string;
}

// McGrew/Viega GCM (2004), Appendix B, AES-256（鍵 256bit・IV 96bit）のベクター。
const VECTORS: readonly CavpVector[] = [
  {
    // Test Case 13: 空の平文・AAD なし。
    name: 'Test Case 13 (AES-256, 空平文, AAD なし)',
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    iv: '000000000000000000000000',
    plaintext: '',
    ciphertext: '',
    tag: '530f8afbc74536b9a963b4f1c4cb738b',
  },
  {
    // Test Case 14: 16 バイト平文・AAD なし。
    name: 'Test Case 14 (AES-256, 16B 平文, AAD なし)',
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    iv: '000000000000000000000000',
    plaintext: '00000000000000000000000000000000',
    ciphertext: 'cea7403d4d606b6e074ec5d3baf39d18',
    tag: 'd0d1c8a799996bf0265b98b5d48ab919',
  },
  {
    // Test Case 16: AAD あり（IV=96bit, AAD 20 バイト, 平文 60 バイト）。
    name: 'Test Case 16 (AES-256, AAD あり)',
    key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    iv: 'cafebabefacedbaddecaf888',
    plaintext:
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    ciphertext:
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
    tag: '76fc6ece0f4e1768cddf8853bb2d551b',
  },
];

describe('AES-256-GCM 既知ベクター適合（McGrew/Viega 2004）', () => {
  for (const v of VECTORS) {
    it(`${v.name}: encryptAesGcmWithIv が CT||Tag を再現する`, async () => {
      const expected = v.ciphertext + v.tag;
      const { iv, ciphertext } = await encryptAesGcmWithIv(
        hexToBytes(v.key),
        hexToBytes(v.iv),
        hexToBytes(v.plaintext),
        v.aad !== undefined ? hexToBytes(v.aad) : undefined,
      );
      expect(toHex(iv)).toBe(v.iv);
      expect(toHex(ciphertext)).toBe(expected);
    });

    it(`${v.name}: decryptAesGcm が期待 PT を返す`, async () => {
      const ctAndTag = hexToBytes(v.ciphertext + v.tag);
      const decrypted = await decryptAesGcm(
        hexToBytes(v.key),
        hexToBytes(v.iv),
        ctAndTag,
        v.aad !== undefined ? hexToBytes(v.aad) : undefined,
      );
      expect(toHex(decrypted)).toBe(v.plaintext);
    });
  }
});

describe('encryptAesGcmWithIv の IV 長前提違反', () => {
  // 32 バイトの有効な鍵（IV 長検証が鍵 import より前に走ることの契約明文化）。
  const KEY = new Uint8Array(32);

  it('IV 長 11 バイトは ENCRYPT_FAILED(1051)', async () => {
    const promise = encryptAesGcmWithIv(KEY, new Uint8Array(11), new Uint8Array(0));
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.ENCRYPT_FAILED });
  });

  it('IV 長 13 バイトは ENCRYPT_FAILED(1051)', async () => {
    const promise = encryptAesGcmWithIv(KEY, new Uint8Array(13), new Uint8Array(0));
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.ENCRYPT_FAILED });
  });
});
