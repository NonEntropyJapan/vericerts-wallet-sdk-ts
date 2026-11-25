/**
 * 署名の正準性 / low-S 相互運用テストで共有するフィクスチャとヘルパ。
 *
 * 実鍵・実署名だけを使い、ハードコードした署名バイト列は持たない（曲線実装の更新に追随させるため）。
 */

import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { EcdsaCurve } from '../../../src/internal/keymanager/signer.js';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  signP256,
  signSecp256k1Recoverable,
} from '../../../src/internal/keymanager/signer.js';

/** hex 文字列をバイト列へ変換する（テスト専用ヘルパ）。 */
export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** バイト列を hex 文字列へ変換する（テスト専用ヘルパ）。 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** テスト用の有効な秘密鍵（32 バイト、RFC6979 のテストベクタ鍵）。 */
export const PRIVATE_KEY = hexToBytes(
  'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
);

/** 32 バイトのテスト用ダイジェスト。 */
export const DIGEST = hexToBytes(
  'af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf',
);

/** 曲線ごとのフィクスチャ（`@noble` 実装・64B raw 署名・圧縮 / 非圧縮公開鍵）。 */
export interface CurveFixture {
  /** 対象曲線の `@noble` ECDSA 実装（high-S 生成の r/s 演算に使う）。 */
  readonly ec: typeof secp256k1;
  /** `DIGEST` に対する正規の 64 バイト P1363 署名（low-S）。 */
  readonly raw: Uint8Array;
  /** 圧縮公開鍵（33 バイト）。 */
  readonly publicKey: Uint8Array;
  /** 非圧縮公開鍵（65 バイト）。 */
  readonly uncompressedPublicKey: Uint8Array;
}

/** 両曲線のフィクスチャ。 */
export const FIXTURES: Record<EcdsaCurve, CurveFixture> = {
  secp256k1: {
    ec: secp256k1,
    raw: signSecp256k1Recoverable(DIGEST, PRIVATE_KEY).signature.subarray(0, 64),
    publicKey: getSecp256k1PublicKey(PRIVATE_KEY),
    uncompressedPublicKey: getSecp256k1PublicKey(PRIVATE_KEY, false),
  },
  p256: {
    ec: p256,
    raw: signP256(DIGEST, PRIVATE_KEY),
    publicKey: getP256PublicKey(PRIVATE_KEY),
    uncompressedPublicKey: getP256PublicKey(PRIVATE_KEY, false),
  },
};

/**
 * 64B raw 署名を high-S（`s > n/2`）へ変換する。
 *
 * `s` を `n - s` に置き換える。ECDSA では両者とも同一鍵・同一 digest に対して数学的に有効であり、
 * KMS / HSM や第三者 Issuer が返し得る「仕様上正当だが low-S ではない」署名を再現する。
 *
 * @param raw 64 バイトの low-S 署名。
 * @param curve 署名の曲線。
 * @returns high-S 版の 64 バイト署名。
 */
export function toHighS(raw: Uint8Array, curve: EcdsaCurve): Uint8Array {
  const { ec } = FIXTURES[curve];
  const sig = ec.Signature.fromBytes(raw, 'compact');
  const flipped = new ec.Signature(sig.r, ec.Point.Fn.ORDER - sig.s);
  if (!flipped.hasHighS()) {
    throw new Error('fixture error: expected a high-S signature');
  }
  return flipped.toBytes('compact');
}

/** 署名バイト列の末尾に 1 バイト付加する（非正準エンコーディングの再現）。 */
export function appendByte(signature: Uint8Array, trailing: number): Uint8Array {
  const out = new Uint8Array(signature.length + 1);
  out.set(signature, 0);
  out[signature.length] = trailing;
  return out;
}
