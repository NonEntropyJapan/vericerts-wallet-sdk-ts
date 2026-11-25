/**
 * 署名の DER ⇔ IEEE P1363 相互変換の振る舞い検証。
 *
 * 両曲線での P1363→DER→P1363 / DER→P1363→DER の往復一致、出力長、
 * 型外曲線（1030）・不正バイト列（1020）のエラーを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  derToP1363,
  type EcdsaCurve,
  p1363ToDer,
  signP256,
  signSecp256k1Recoverable,
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

const PRIVATE_KEY = hexToBytes('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721');
const DIGEST = hexToBytes('af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf');

/** 各曲線の 64 バイト P1363 署名を用意する。 */
const RAW_BY_CURVE: Record<EcdsaCurve, Uint8Array> = {
  secp256k1: signSecp256k1Recoverable(DIGEST, PRIVATE_KEY).signature.subarray(0, 64),
  p256: signP256(DIGEST, PRIVATE_KEY),
};

describe.each<EcdsaCurve>(['secp256k1', 'p256'])('DER ⇔ P1363 conversion (%s)', (curve) => {
  const raw = RAW_BY_CURVE[curve];

  it('round-trips P1363 → DER → P1363 to the original bytes', () => {
    const der = p1363ToDer(raw, curve);
    const back = derToP1363(der, curve);
    expect(toHex(back)).toBe(toHex(raw));
  });

  it('round-trips DER → P1363 → DER to the original bytes', () => {
    const der = p1363ToDer(raw, curve);
    const roundTripDer = p1363ToDer(derToP1363(der, curve), curve);
    expect(toHex(roundTripDer)).toBe(toHex(der));
  });

  it('produces a 64-byte P1363 from DER', () => {
    const der = p1363ToDer(raw, curve);
    expect(derToP1363(der, curve).length).toBe(64);
  });

  it('throws SIGN_FAILED (1020) for invalid DER bytes', () => {
    let caught: unknown;
    try {
      derToP1363(hexToBytes('deadbeef'), curve);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.SIGN_FAILED);
  });

  it('throws SIGN_FAILED (1020) for an invalid-length P1363 raw (63 bytes)', () => {
    let caught: unknown;
    try {
      // 64 バイトでない不正長の raw（63 バイト）は署名演算失敗に正規化される。
      p1363ToDer(raw.subarray(0, 63), curve);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.SIGN_FAILED);
  });
});

describe('unsupported curve normalization', () => {
  it('throws UNSUPPORTED_ALGORITHM (1030) for an out-of-type curve in derToP1363', () => {
    let caught: unknown;
    try {
      derToP1363(RAW_BY_CURVE.p256, 'ed25519' as unknown as EcdsaCurve);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
  });

  it('throws UNSUPPORTED_ALGORITHM (1030) for an out-of-type curve in p1363ToDer', () => {
    let caught: unknown;
    try {
      p1363ToDer(RAW_BY_CURVE.p256, 'ed25519' as unknown as EcdsaCurve);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
  });
});
