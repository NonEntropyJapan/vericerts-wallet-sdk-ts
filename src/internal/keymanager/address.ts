/**
 * keymanager の鍵 ID・Ethereum アドレス導出ヘルパ（純粋関数）。
 *
 * `KeyManager` facade から切り出した自己完結なバイト演算ユーティリティ。秘密鍵・公開鍵の
 * バイト列を入力に、安定鍵 ID（公開鍵の SHA-256 hex）と EIP-55 チェックサム付き Ethereum
 * アドレスを導出する。状態を持たず、入力をそのまま例外に含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { toEip55Hex } from '../evm-format.js';
import { getSecp256k1PublicKey } from './signer.js';

/** keccak256 ダイジェスト（32 バイト）を返す。 */
export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

/** 公開鍵の SHA-256 ハッシュ（hex）を鍵 ID として返す。 */
export function computeKeyId(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey));
}

/**
 * 秘密鍵から EIP-55 チェックサム付き Ethereum アドレスを導出する。
 *
 * 非圧縮公開鍵（65 バイト）の先頭 `0x04` を除いた 64 バイトを keccak256 し、
 * 下位 20 バイトをアドレスとする。さらに EIP-55 のチェックサム規則で英字を大文字化する。
 *
 * @param privateKey 秘密鍵（32 バイト）。
 * @returns `0x` + 40 hex（EIP-55）形式のアドレス。
 */
export function deriveEip55Address(privateKey: Uint8Array): string {
  // 非圧縮 65 バイトを取得し、先頭 0x04 を除いた 64 バイトを使う。
  const uncompressed = getSecp256k1PublicKey(privateKey, false);
  const hash = keccak_256(uncompressed.subarray(1));
  const addressBytes = hash.subarray(hash.length - 20);
  const lowerHex = bytesToHex(addressBytes);
  return `0x${toEip55Hex(lowerHex)}`;
}
