/**
 * secp256k1 署名・検証・公開鍵復元の振る舞い検証。
 *
 * 署名→検証のラウンドトリップ、RFC6979 決定性、recovery からの公開鍵復元、
 * low-s 正規化、改ざん検出、鍵長不正のエラー、公開鍵の圧縮/非圧縮長を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  getSecp256k1PublicKey,
  recoverSecp256k1PublicKey,
  signSecp256k1Recoverable,
  verifySecp256k1,
} from '../../signer.js';

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

// テスト用の有効な秘密鍵（32 バイト）。
const PRIVATE_KEY = hexToBytes('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721');
// 32 バイトのテスト用ダイジェスト。
const DIGEST = hexToBytes('af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf');

describe('signSecp256k1Recoverable / verifySecp256k1', () => {
  it('signs and verifies (round-trip) with the compressed public key', () => {
    const { signature, recovery } = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);
    expect(signature.length).toBe(65);
    expect(recovery === 0 || recovery === 1).toBe(true);
    expect(signature[64]).toBe(recovery);
    const pub = getSecp256k1PublicKey(PRIVATE_KEY);
    // 65 バイトの recovery 付き形式は JWS の正準形式ではないため、明示的な opt-in が要る。
    expect(verifySecp256k1(DIGEST, signature, pub, { encoding: 'recovered' })).toBe(true);
  });

  it('verifies a 64-byte (r||s) signature as well', () => {
    const { signature } = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);
    const compact = signature.subarray(0, 64);
    const pub = getSecp256k1PublicKey(PRIVATE_KEY);
    expect(verifySecp256k1(DIGEST, compact, pub)).toBe(true);
  });

  it('is deterministic (RFC6979): same input yields byte-identical signatures', () => {
    const first = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);
    const second = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);
    expect(toHex(first.signature)).toBe(toHex(second.signature));
    expect(first.recovery).toBe(second.recovery);
  });

  it('produces a low-S signature (s <= n/2)', () => {
    const { signature } = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);
    const s = BigInt(`0x${toHex(signature.subarray(32, 64))}`);
    // secp256k1 の位数 n の半分。low-s では s <= n/2 を満たす。
    const HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
    expect(s <= HALF_N).toBe(true);
  });

  it('detects tampering (flipped digest fails verification)', () => {
    const { signature } = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);
    const compact = signature.subarray(0, 64);
    const pub = getSecp256k1PublicKey(PRIVATE_KEY);
    const tampered = new Uint8Array(DIGEST);
    tampered.set([(tampered[0] ?? 0) ^ 0xff], 0);

    // 未改ざんなら通ることを先に固定する。これが無いと「長さチェックで落ちているだけ」の
    // 空虚なテストになり得る（既定を厳密 64 バイトへ狭めた際の回帰）。
    expect(verifySecp256k1(DIGEST, compact, pub)).toBe(true);
    expect(verifySecp256k1(DIGEST, signature, pub, { encoding: 'recovered' })).toBe(true);

    // 64 バイト（既定の p1363）と 65 バイト（recovered opt-in）の両形式で改ざんを検出する。
    expect(verifySecp256k1(tampered, compact, pub)).toBe(false);
    expect(verifySecp256k1(tampered, signature, pub, { encoding: 'recovered' })).toBe(false);
  });

  it('throws INVALID_PRIVATE_KEY (1003) for a wrong-length private key', () => {
    let caught: unknown;
    try {
      signSecp256k1Recoverable(DIGEST, hexToBytes('00112233'));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_PRIVATE_KEY);
  });

  it('throws SIGN_FAILED (1020) for a digest that is not 32 bytes', () => {
    let caught: unknown;
    try {
      signSecp256k1Recoverable(hexToBytes('0011'), PRIVATE_KEY);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.SIGN_FAILED);
  });
});

describe('getSecp256k1PublicKey', () => {
  it('returns a 33-byte compressed public key by default', () => {
    expect(getSecp256k1PublicKey(PRIVATE_KEY).length).toBe(33);
  });

  it('returns a 65-byte uncompressed public key when compressed=false', () => {
    expect(getSecp256k1PublicKey(PRIVATE_KEY, false).length).toBe(65);
  });

  it('throws INVALID_PRIVATE_KEY (1003) for an invalid private key', () => {
    let caught: unknown;
    try {
      getSecp256k1PublicKey(new Uint8Array(32));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_PRIVATE_KEY);
  });
});

describe('recoverSecp256k1PublicKey', () => {
  it('recovers the compressed public key matching getSecp256k1PublicKey', () => {
    const { signature } = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);
    const recovered = recoverSecp256k1PublicKey(DIGEST, signature);
    expect(toHex(recovered)).toBe(toHex(getSecp256k1PublicKey(PRIVATE_KEY)));
  });

  it('recovers the uncompressed public key when compressed=false', () => {
    const { signature } = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);
    const recovered = recoverSecp256k1PublicKey(DIGEST, signature, false);
    expect(recovered.length).toBe(65);
    expect(toHex(recovered)).toBe(toHex(getSecp256k1PublicKey(PRIVATE_KEY, false)));
  });

  it('throws SIGN_FAILED (1020) for a recoverable signature that is not 65 bytes', () => {
    let caught: unknown;
    try {
      recoverSecp256k1PublicKey(DIGEST, new Uint8Array(64));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.SIGN_FAILED);
  });
});

describe('secret material non-leakage', () => {
  it('does not include the private key hex in error messages', () => {
    const privateKeyHex = toHex(PRIVATE_KEY);
    let thrown: unknown;
    try {
      // digest 長不正で SIGN_FAILED に到達させる。
      signSecp256k1Recoverable(hexToBytes('00'), PRIVATE_KEY);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    const message = (thrown as VericertsError).message;
    expect(message).toBe('署名演算に失敗しました');
    expect(message).not.toContain(privateKeyHex);
  });
});
