/**
 * did:ipid テスト用の CID 生成（Kubo `add?cid-version=1` が単一ブロックのファイルに返す形）。
 *
 * CIDv1 / codec `raw`(0x55) / `sha2-256` を multibase base32（小文字、接頭辞 `b`）で表す。
 * 本番コード（`cid.ts`）は検証のみを持つため、生成側はテストだけが必要とする。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base32nopad, base58 } from '@scure/base';

/** 本文（UTF-8）の raw sha2-256 CIDv1 を返す。 */
export function rawCidOf(text: string): string {
  const digest = sha256(new TextEncoder().encode(text));
  // <version=1><codec=raw><hash=sha2-256><len=32><digest>
  const cidBytes = new Uint8Array([0x01, 0x55, 0x12, 0x20, ...digest]);
  return `b${base32nopad.encode(cidBytes).toLowerCase()}`;
}

/** CID バイト列を multibase base36（小文字、接頭辞 `k`）にする。Kubo / ブラウザが CID を表示する標準形。 */
export function toBase36(bytes: Uint8Array): string {
  let n = 0n;
  for (const byte of bytes) {
    n = (n << 8n) | BigInt(byte);
  }
  return `k${n.toString(36)}`;
}

/** 本文（UTF-8）の raw sha2-256 CIDv1 を base36（`k...`）表記で返す。 */
export function rawCidBase36Of(text: string): string {
  const digest = sha256(new TextEncoder().encode(text));
  return toBase36(new Uint8Array([0x01, 0x55, 0x12, 0x20, ...digest]));
}

/** 本文（UTF-8）の sha2-256 CIDv0（`Qm...`、base58btc の multihash）を返す。 */
export function cidV0Of(text: string): string {
  const digest = sha256(new TextEncoder().encode(text));
  return base58.encode(new Uint8Array([0x12, 0x20, ...digest]));
}

/**
 * Ed25519 公開鍵（32B）を埋め込んだ libp2p-key の IPNS 名（CIDv1 `libp2p-key`(0x72)・multihash
 * `identity`、base36 `k51...`）。Kubo の `name/publish` が返す形。
 */
export function ipnsNameOf(seed: number): string {
  // 署名検証が通るよう、`seed` を 32 バイトに敷いた秘密鍵から実際の公開鍵を導出する。
  const publicKey = ed25519.getPublicKey(new Uint8Array(32).fill(seed));
  const protobufKey = [0x08, 0x01, 0x12, 0x20, ...publicKey];
  return toBase36(new Uint8Array([0x01, 0x72, 0x00, protobufKey.length, ...protobufKey]));
}
