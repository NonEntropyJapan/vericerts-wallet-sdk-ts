/**
 * did:webvh v1.0 の SHA-256 multihash（base58btc、multibase の `z` プレフィックスなし）。
 *
 * spec: DIF didwebvh v1.0「SCID Generation and Verification」（`base58btc(multihash(JCS(...)))`）、
 * 「Entry Hash Generation and Verification」、「Pre-Rotation Key Hash Generation and Verification」。
 * SCID・entryHash・`nextKeyHashes` はいずれも `Qm...`（46 文字）形式で、`z` を付けない
 * （`../multibase.ts` の multibase base58btc とは別物）。
 *
 * 例外メッセージ・`context` に入力値を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base58 } from '@scure/base';

/** sha2-256 の multicodec コード。 */
const MULTICODEC_SHA2_256 = 0x12;

/** SHA-256 ダイジェスト長（バイト）。 */
const SHA2_256_LENGTH = 32;

/** multihash 全体の長さ（ヘッダ 2 + ダイジェスト 32）。 */
const MULTIHASH_LENGTH = 2 + SHA2_256_LENGTH;

/** SHA-256 multihash の base58btc 表記の長さ（`Qm` + 44 文字）。base58 デコード（二次時間）の前に長さで縛る。 */
export const MULTIHASH_BASE58_LENGTH = 46;

/** 生の base58btc 文字（Bitcoin アルファベット）。 */
const BASE58_BODY = /^[1-9A-HJ-NP-Za-km-z]+$/;

/**
 * バイト列の SHA-256 multihash を base58btc（`z` なし）にする。
 *
 * @param bytes ハッシュ対象。
 * @returns base58btc(0x12 || 0x20 || digest)。
 */
export function multihashBase58(bytes: Uint8Array): string {
  const digest = sha256(bytes);
  const multihash = new Uint8Array(MULTIHASH_LENGTH);
  multihash[0] = MULTICODEC_SHA2_256;
  multihash[1] = SHA2_256_LENGTH;
  multihash.set(digest, 2);
  return base58.encode(multihash);
}

/** 文字列を UTF-8 にして SHA-256 multihash（base58btc）を計算する。 */
export function multihashOfText(text: string): string {
  return multihashBase58(new TextEncoder().encode(text));
}

/**
 * 文字列が SHA-256 multihash の base58btc 表記（46 文字）か。例外は投げない。
 *
 * v1.0 が許すハッシュは SHA-256（multihash コード `0x12`）だけで、他のアルゴリズムは拒否する
 * （spec: `method` パラメータ `did:webvh:1.0` の Permitted hash algorithms）。
 */
export function isSha256MultihashBase58(text: unknown): text is string {
  if (
    typeof text !== 'string' ||
    text.length !== MULTIHASH_BASE58_LENGTH ||
    !BASE58_BODY.test(text)
  ) {
    return false;
  }
  try {
    const decoded = base58.decode(text);
    return (
      decoded.length === MULTIHASH_LENGTH &&
      decoded[0] === MULTICODEC_SHA2_256 &&
      decoded[1] === SHA2_256_LENGTH
    );
  } catch {
    return false;
  }
}
