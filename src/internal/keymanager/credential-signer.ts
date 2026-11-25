/**
 * KeyManager の鍵を非公開のまま JWS 署名するための署名鍵ビルダ（純粋関数）。
 *
 * `KeyManager`（Foundation）は credential（Domain）を import しないため（レイヤリング厳守）、
 * credential の `CredentialSigner` とは構造的に互換な `CredentialSigningKey` を返す。
 * KeyManager クラスはこのビルダへ委譲する薄い facade に徹する（keymanager.ts と同じ責務分担）。
 *
 * 対応する鍵は secp256k1（`alg: ES256K`、RFC 8812）と P-256（`alg: ES256`、RFC 7518 §3.4）。
 * どちらも signing-input の SHA-256 に ECDSA 署名し、64 バイトの `r || s` を返す。
 *
 * セキュリティ上の注意:
 * - privateKey は戻り値・例外に一切含めない（公開鍵座標 / 署名のみを返す）。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  signP256,
  signSecp256k1Recoverable,
} from './signer.js';

/**
 * JWS 署名鍵（credential `CredentialSigner` と構造的に互換な型）。
 *
 * KeyManager の鍵を露出せずに JWS 署名できるよう、`alg` / `publicKeyJwk` / `sign` のみを公開する。
 */
export interface CredentialSigningKey {
  /** JWS 署名アルゴリズム。secp256k1 は `ES256K`、P-256 は `ES256`。 */
  readonly alg: 'ES256K' | 'ES256';
  /** 署名者の EC 公開鍵 JWK（`{ kty:'EC', crv:'secp256k1' | 'P-256', x, y }`）。 */
  readonly publicKeyJwk: Readonly<Record<string, unknown>>;
  /**
   * signing-input のバイト列に署名し、64 バイト raw 署名（`r || s`）を返す。
   * @param signingInput `base64url(header).base64url(payload)` の UTF-8 バイト列。
   * @returns 64 バイトの raw 署名。
   */
  sign(signingInput: Uint8Array): Uint8Array;
}

/** 非圧縮公開鍵（`0x04 || x(32) || y(32)`）の座標を EC 公開鍵 JWK にする。 */
function toEcJwk(uncompressed: Uint8Array, crv: 'secp256k1' | 'P-256'): Record<string, unknown> {
  return {
    kty: 'EC',
    crv,
    x: base64urlnopad.encode(uncompressed.subarray(1, 33)),
    y: base64urlnopad.encode(uncompressed.subarray(33, 65)),
  };
}

/**
 * secp256k1 秘密鍵から JWT-VC 署名鍵（`CredentialSigningKey`）を構築する。
 *
 * `sign` は signing-input の SHA-256 を `signSecp256k1Recoverable` で署名し、JWS は recovery 不要の
 * ため先頭 64 バイト（`r || s`）を返す。privateKey はクロージャに閉じ込め、戻り値に露出しない。
 *
 * @param privateKey secp256k1 秘密鍵（32 バイト）。
 * @returns 構造的に `CredentialSigner` と互換な署名鍵（`alg: 'ES256K'`）。
 */
export function createSecp256k1CredentialSigner(privateKey: Uint8Array): CredentialSigningKey {
  return {
    alg: 'ES256K',
    publicKeyJwk: toEcJwk(getSecp256k1PublicKey(privateKey, false), 'secp256k1'),
    sign: (signingInput: Uint8Array): Uint8Array => {
      const digest = sha256(signingInput);
      return signSecp256k1Recoverable(digest, privateKey).signature.subarray(0, 64);
    },
  };
}

/**
 * P-256 秘密鍵から JWS 署名鍵（`CredentialSigningKey`）を構築する（ES256）。
 *
 * `sign` は signing-input の SHA-256 に対する決定論的 ECDSA（RFC 6979・low-S）の 64 バイト `r || s`。
 *
 * @param privateKey P-256 秘密鍵（32 バイト）。
 * @returns 構造的に `CredentialSigner` と互換な署名鍵（`alg: 'ES256'`）。
 */
export function createP256CredentialSigner(privateKey: Uint8Array): CredentialSigningKey {
  return {
    alg: 'ES256',
    publicKeyJwk: toEcJwk(getP256PublicKey(privateKey, false), 'P-256'),
    sign: (signingInput: Uint8Array): Uint8Array => signP256(sha256(signingInput), privateKey),
  };
}
