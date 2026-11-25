/**
 * 「ZIP215 でのみ有効」な Ed25519 署名を組み立てるテスト用フィクスチャ。
 *
 * `@noble/curves` の `ed25519.verify` は既定が `zip215: true` で、点の「非正準エンコーディング」
 * （`y >= p` の表現）まで受理する。SDK の `EdDSA-Ed25519@1.0` は RFC 8032 に従い、非正準エンコーディングを拒否する。既定のままだと他 Verifier が
 * 拒否する署名を本 SDK だけが受理し、同一 VC の検証結果が実装間で割れる。
 *
 * ここで作る署名は「ZIP215 では有効・RFC 8032 では無効」という差分そのものなので、
 * `verifyEd25519`（`zip215: false`）を経由しているかどうかを検証経路ごとに判別できる。
 * webvh の proof 検証・ARF Catalogue のエンベロープ検証など、複数の呼び出し経路が同じ
 * 受理集合であることを確かめるために共有する。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';

/** Ed25519 の群位数 L（RFC 8032 §5.1）。 */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/** 素体の位数 p = 2^255 - 19。`y = p` は `y = 0` の非正準表現になる。 */
const P = (1n << 255n) - 19n;

/** Ed25519 のシード / スカラー / 点エンコーディングの長さ（バイト）。 */
const FIELD_LENGTH = 32;

/** bigint をリトルエンディアン 32 バイトへ変換する。 */
function toLE(value: bigint): Uint8Array {
  const bytes = new Uint8Array(FIELD_LENGTH);
  for (let i = 0; i < FIELD_LENGTH; i++) {
    bytes[i] = Number((value >> BigInt(8 * i)) & 0xffn);
  }
  return bytes;
}

/** リトルエンディアンのバイト列を bigint へ変換する。 */
function fromLE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i] ?? 0);
  }
  return value;
}

/**
 * R を非正準エンコーディングにした「ZIP215 でのみ有効」な署名を組み立てる。
 *
 * `S = k * a mod L`（`k = SHA-512(R || A || M) mod L`、`a` は RFC 8032 §5.1.5 の clamp 済みスカラー）
 * とすることで検証式 `[S]B = R + [k]A` を成立させる。R のバイト列は `y = p`（= `y = 0` と同じ点を
 * 指す非正準表現）なので、RFC 8032 では復号段階で拒否される。
 *
 * @param seed Ed25519 秘密鍵シード（32 バイト）。公開鍵はここから導出する。
 * @param message 署名対象メッセージ（検証経路が実際に組み立てる署名対象バイト列）。
 * @returns 64 バイトの署名（`R(32) || S(32)`）。
 */
export function buildZip215OnlySignature(seed: Uint8Array, message: Uint8Array): Uint8Array {
  const hashed = sha512(seed);
  const head = hashed.slice(0, FIELD_LENGTH);
  // RFC 8032 §5.1.5 の clamp。
  head[0] = (head[0] ?? 0) & 248;
  head[31] = ((head[31] ?? 0) & 127) | 64;
  const scalar = fromLE(head) % L;

  const publicKey = ed25519.getPublicKey(seed);
  const rEncoded = toLE(P); // y = p（非正準。指す点は y = 0 と同じ）
  const k = fromLE(sha512(new Uint8Array([...rEncoded, ...publicKey, ...message]))) % L;
  return new Uint8Array([...rEncoded, ...toLE((k * scalar) % L)]);
}

/**
 * 署名が ZIP215（`@noble` の既定）では有効と判定されることを確かめる。
 *
 * 各テストで「フィクスチャが本当に ZIP215 限定で有効か」を前提確認するために使う。
 * これが `true` でなければ、拒否のテストは単に壊れた署名を拒否しているだけで空虚になる。
 */
export function acceptedUnderZip215(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return ed25519.verify(signature, message, publicKey, { zip215: true });
}
