/**
 * trust/arf テスト用フィクスチャ生成。
 *
 * ARF Catalogue の署名エンベロープ（catalogue.ts が検証する detached Ed25519・JWS ライク形式）を
 * 本物の @noble/curves の Ed25519 鍵で生成する。SPKI 突き合わせ用の X.509 証明書は etsi-tsl の
 * `makeCertificate` を流用する。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { base64, base64urlnopad } from '@scure/base';

/** テスト用の Ed25519 鍵ペア。 */
export interface Ed25519KeyPair {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

/** 固定シードから決定的な Ed25519 鍵ペアを作る。 */
export function makeKeyPair(seed = 7): Ed25519KeyPair {
  const secretKey = new Uint8Array(32).fill(seed);
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

/** ARF Catalogue payload の入力（テスト用の緩い型）。 */
export interface CataloguePayload {
  readonly version?: string;
  /** 鮮度・世代の項目。不正値の拒否を試せるよう緩い型にしている。 */
  readonly sequence?: unknown;
  readonly issuedAt?: unknown;
  readonly nextUpdate?: unknown;
  readonly entries: unknown[];
}

/**
 * payload を base64url 化し、その文字列バイト列に任意の署名関数で署名したエンベロープ JSON を返す。
 *
 * 署名対象は catalogue.ts の `verifyEnvelope` と同じ「payload（base64url 文字列）の UTF-8 バイト列」。
 * 不正・非正準な署名を差し込むテスト用に、署名生成を差し替えられるようにしている。
 */
export function catalogueEnvelope(
  payload: CataloguePayload,
  sign: (message: Uint8Array) => Uint8Array,
): string {
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = base64urlnopad.encode(new TextEncoder().encode(payloadJson));
  const signature = sign(new TextEncoder().encode(payloadB64));
  return JSON.stringify({ payload: payloadB64, signature: base64.encode(signature) });
}

/**
 * payload を base64url 化し、その文字列バイト列に Ed25519 署名を付けたエンベロープ JSON を返す。
 * catalogue.ts の `verifyEnvelope` / `decodePayload` が受理する正当な形式。
 */
export function signedCatalogue(payload: CataloguePayload, key: Ed25519KeyPair): string {
  return catalogueEnvelope(payload, (message) => ed25519.sign(message, key.secretKey));
}

/** SPKI（DER）を base64 文字列にする（Catalogue エントリの `spki` フィールド用）。 */
export function spkiToBase64(spki: Uint8Array): string {
  return base64.encode(spki);
}
