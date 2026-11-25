/**
 * P-256 署名・検証の振る舞い検証。
 *
 * RFC6979 既知ベクター（P-256 / SHA-256）での r,s 固定値一致、署名→検証ラウンドトリップ、
 * 改ざん検出、出力長（64 バイト P1363）、鍵不正のエラーを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getP256PublicKey, signP256, verifyP256 } from '../../signer.js';

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

// RFC 6979 §A.2.5（P-256, SHA-256）の秘密鍵。
const PRIVATE_KEY = hexToBytes('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721');
// RFC 6979 §A.2.5 のメッセージ "sample" の SHA-256 ダイジェスト。
const SAMPLE_DIGEST = hexToBytes(
  'af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf',
);
// RFC 6979 §A.2.5 の r。
const KAT_R = 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716';
// low-S 正規化済みの s（= n - s_rfc）。署名 KAT テストの期待値と同一。
const KAT_S = '0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9';

describe('signP256 known-answer (RFC6979 P-256/SHA-256, message "sample")', () => {
  it('produces the RFC6979 r and the low-S normalized s', () => {
    const sig = signP256(SAMPLE_DIGEST, PRIVATE_KEY);
    expect(sig.length).toBe(64);
    const r = toHex(sig.subarray(0, 32));
    const s = toHex(sig.subarray(32, 64));
    // r は RFC 6979 §A.2.5 の期待値と一致する。
    expect(r).toBe('efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716');
    // s は @noble の low-S 正規化により n - s_rfc となる（malleability 防止）。
    expect(s).toBe('0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9');
  });
});

describe('verifyP256 known-answer (RFC6979 P-256/SHA-256, message "sample")', () => {
  it('verifies a hard-coded RFC6979 signature (independent of signP256)', () => {
    // 署名関数で生成せず、ハードコードした既知署名バイト列（r || s）で verify を独立検証する。
    const knownSig = hexToBytes(KAT_R + KAT_S);
    const pub = getP256PublicKey(PRIVATE_KEY);
    expect(verifyP256(SAMPLE_DIGEST, knownSig, pub)).toBe(true);
  });
});

describe('signP256 / verifyP256', () => {
  it('signs and verifies (round-trip)', () => {
    const sig = signP256(SAMPLE_DIGEST, PRIVATE_KEY);
    const pub = getP256PublicKey(PRIVATE_KEY);
    expect(verifyP256(SAMPLE_DIGEST, sig, pub)).toBe(true);
  });

  it('outputs a 64-byte P1363 signature', () => {
    expect(signP256(SAMPLE_DIGEST, PRIVATE_KEY).length).toBe(64);
  });

  it('detects tampering (flipped digest fails verification)', () => {
    const sig = signP256(SAMPLE_DIGEST, PRIVATE_KEY);
    const pub = getP256PublicKey(PRIVATE_KEY);
    const tampered = new Uint8Array(SAMPLE_DIGEST);
    tampered.set([(tampered[0] ?? 0) ^ 0xff], 0);
    expect(verifyP256(tampered, sig, pub)).toBe(false);
  });

  it('throws INVALID_PRIVATE_KEY (1003) for an invalid private key', () => {
    let caught: unknown;
    try {
      signP256(SAMPLE_DIGEST, hexToBytes('00112233'));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_PRIVATE_KEY);
  });

  it('throws SIGN_FAILED (1020) for a digest that is not 32 bytes', () => {
    let caught: unknown;
    try {
      signP256(hexToBytes('0011'), PRIVATE_KEY);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.SIGN_FAILED);
  });
});

describe('getP256PublicKey', () => {
  it('returns a 33-byte compressed public key by default', () => {
    expect(getP256PublicKey(PRIVATE_KEY).length).toBe(33);
  });

  it('returns a 65-byte uncompressed public key when compressed=false', () => {
    expect(getP256PublicKey(PRIVATE_KEY, false).length).toBe(65);
  });

  it('throws INVALID_PRIVATE_KEY (1003) for an invalid private key', () => {
    let caught: unknown;
    try {
      getP256PublicKey(new Uint8Array(32));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_PRIVATE_KEY);
  });
});
