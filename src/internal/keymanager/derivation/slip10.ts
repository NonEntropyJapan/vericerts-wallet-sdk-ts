/**
 * SLIP-0010（Universal private key derivation from master private key）の NIST P-256 鍵導出。
 *
 * 新規作成する DID（did:key / did:jwk / did:peer）の鍵は P-256（ES256）で、シードから本モジュールで
 * 決定的に導出する。ニーモニックだけで全ての鍵が復元できる（key-lifecycle の復元不変条件）。
 *
 * 規格どおりの手順（https://github.com/satoshilabs/slips/blob/master/slip-0010.md）:
 * - マスター鍵: `I = HMAC-SHA512(Key = "Nist256p1 seed", Data = S)`。`I_L` が 0 または n 以上なら
 *   `S := I` で再試行する。
 * - 子鍵 CKDpriv: hardened は `0x00 || ser256(k_par) || ser32(i)`、通常は `serP(point(k_par)) || ser32(i)`。
 *   `I_L >= n` または子鍵が 0 になる場合は `0x01 || I_R || ser32(i)` で再試行する（BIP-32 のように失敗しない）。
 *
 * レガシー secp256k1 の BIP-32 導出（`hd.ts`、`m/44'/60'/<index>'/0/0`）とは**別系統**である。
 * HMAC 鍵が `"Bitcoin seed"` と `"Nist256p1 seed"` で異なるため、同じ seed・同じパス文字列でも
 * 両者が同一の秘密鍵を返すことはない。さらに DID 鍵のパス（{@link p256DidPath}）は purpose を
 * `9256'` として `44'/60'` とも区別する。
 *
 * セキュリティ上の注意: seed / 秘密鍵 / chain code / パス文字列を例外へ含めない。
 */

import { p256 } from '@noble/curves/nist.js';
import { bytesToNumberBE, concatBytes, numberToBytesBE } from '@noble/curves/utils.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../errors.js';

/** SLIP-0010 が NIST P-256 に割り当てるマスター鍵の HMAC キー。 */
const NIST256P1_SEED_KEY = new TextEncoder().encode('Nist256p1 seed');

/** hardened 子鍵の最小インデックス（2^31）。 */
const HARDENED_OFFSET = 0x80000000;

/** SLIP-0010 / BIP-32 が受け付ける seed 長（128〜512 bit）。 */
const MIN_SEED_BYTES = 16;
const MAX_SEED_BYTES = 64;

/** P-256 のグループ位数 n。 */
const CURVE_ORDER = p256.Point.Fn.ORDER;

/**
 * DID 鍵（P-256）の導出パスの purpose。BIP-43 に倣う未登録の自家用番号で、BIP-44 の `44'` とも
 * SLIP-0044 の coin type とも衝突しない。レガシー secp256k1 のペルソナ鍵（`m/44'/60'/<index>'/0/0`）と
 * パス文字列の上でも交わらないようにするための選択で、一度公開したら変更しない（変更すると復元できない）。
 */
export const P256_DID_PURPOSE = 9256;

/**
 * SLIP-0010 で導出した NIST P-256 鍵素材。
 */
export interface Slip10Key {
  /** 秘密鍵（32 バイト）。 */
  readonly privateKey: Uint8Array;
  /** 公開鍵（圧縮形式・33 バイト）。 */
  readonly publicKey: Uint8Array;
  /** チェーンコード（32 バイト）。 */
  readonly chainCode: Uint8Array;
  /** この鍵を導出したパス（例: `m/9256'/0'/0'/0'`）。 */
  readonly derivationPath: string;
}

/**
 * ペルソナ index から DID 鍵（P-256）の SLIP-0010 導出パスを組み立てる。
 *
 * 形式は `m/9256'/0'/<index>'/0'`。SLIP-0010 は NIST P-256 に hardened と通常（non-hardened）の両方を定義するが、
 * 本ウォレットの DID 鍵のパスは全 hardened に制限する（方針。通常の子鍵が混じると、親の公開鍵と子の秘密鍵から
 * 親の秘密鍵が計算できてしまう。`key-registry.ts` が拒否する）。
 *
 * @param index ペルソナ index（非負整数、2^31 未満）。
 * @returns 導出パス文字列。
 * @throws `index` が範囲外の場合（VericertsError、code `1040`）。
 */
export function p256DidPath(index: number): string {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  return `m/${P256_DID_PURPOSE}'/0'/${index}'/0'`;
}

/** `m` または `m/<n>['](/<n>['])*` の構文。 */
const PATH_PATTERN = /^m(\/\d+'?)*$/;

/** パスをインデックス列（hardened は 2^31 加算済み）に分解する。不正なら `1040`。 */
function parsePath(path: string): number[] {
  if (!PATH_PATTERN.test(path)) {
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  return path
    .split('/')
    .slice(1)
    .map((segment) => {
      const hardened = segment.endsWith("'");
      const value = Number(hardened ? segment.slice(0, -1) : segment);
      if (!Number.isSafeInteger(value) || value >= HARDENED_OFFSET) {
        throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
      }
      return hardened ? value + HARDENED_OFFSET : value;
    });
}

/** `ser32(i)`（4 バイト big-endian）。 */
function ser32(index: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, index, false);
  return out;
}

/** マスター鍵（`m`）の導出。 */
function masterKey(seed: Uint8Array): { key: Uint8Array; chainCode: Uint8Array } {
  let data = seed;
  for (;;) {
    const i = hmac(sha512, NIST256P1_SEED_KEY, data);
    const left = bytesToNumberBE(i.subarray(0, 32));
    if (left !== 0n && left < CURVE_ORDER) {
      return { key: i.slice(0, 32), chainCode: i.slice(32) };
    }
    // 無効な鍵: 中間ハッシュを新しい seed として再試行する（SLIP-0010 マスター鍵の step 4）。
    data = i;
  }
}

/** CKDpriv（SLIP-0010 の NIST P-256）。無効な子鍵は規格どおり再試行する。 */
function childKey(
  parent: { key: Uint8Array; chainCode: Uint8Array },
  index: number,
): { key: Uint8Array; chainCode: Uint8Array } {
  const parentNumber = bytesToNumberBE(parent.key);
  const hardened = index >= HARDENED_OFFSET;
  let data = hardened
    ? concatBytes(new Uint8Array([0]), parent.key, ser32(index))
    : concatBytes(p256.getPublicKey(parent.key, true), ser32(index));
  for (;;) {
    const i = hmac(sha512, parent.chainCode, data);
    const left = bytesToNumberBE(i.subarray(0, 32));
    const child = (left + parentNumber) % CURVE_ORDER;
    if (left < CURVE_ORDER && child !== 0n) {
      return { key: numberToBytesBE(child, 32), chainCode: i.slice(32) };
    }
    // 無効な子鍵: `0x01 || I_R || ser32(i)` で再試行する（CKDpriv の step 5）。
    data = concatBytes(new Uint8Array([1]), i.subarray(32), ser32(index));
  }
}

/**
 * シードと SLIP-0010 パスから NIST P-256（`"Nist256p1 seed"`）の鍵を導出する。
 *
 * 規格どおり hardened / 通常の両方の子鍵導出に対応する（公式テストベクタ検証のため）。
 * KeyManager 経由の DID 鍵導出は、方針として全 hardened のパス（{@link p256DidPath}）だけを受け付ける。
 *
 * @param seed BIP-39 シード等（16〜64 バイト）。
 * @param path 導出パス（例: `m/0'/1/2'`）。
 * @returns 導出した鍵素材。
 * @throws seed 長・パスが不正な場合（VericertsError、code `1040`）。
 */
export function deriveSlip10Nist256p1(seed: Uint8Array, path: string): Slip10Key {
  if (seed.length < MIN_SEED_BYTES || seed.length > MAX_SEED_BYTES) {
    throw new VericertsError(ErrorCodes.DERIVATION_PATH_INVALID);
  }
  let node = masterKey(seed);
  for (const index of parsePath(path)) {
    node = childKey(node, index);
  }
  return {
    privateKey: node.key,
    publicKey: p256.getPublicKey(node.key, true),
    chainCode: node.chainCode,
    derivationPath: path,
  };
}
