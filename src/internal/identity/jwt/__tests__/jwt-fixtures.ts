/**
 * did:jwt 解決テスト用の共有フィクスチャ（実鍵での JWT 署名）。
 *
 * `method-jwt.resolve.test.ts` /
 * `method-jwt.errors.test.ts` から共有する（モック禁止・実鍵で署名）。
 *
 * エンコード・署名・did:jwt 組み立ては本番の `generate.ts`（`assembleDidJwt`）に委譲し、
 * ロジックの重複を排除する。本フィクスチャは header / payload の上書き・署名改竄など
 * 「異常系を作る」ための薄いラッパに徹する。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  signP256,
  signSecp256k1Recoverable,
} from '../../../keymanager/signer.js';
import { assembleDidJwt } from '../generate.js';

/** テスト用の固定現在時刻（エポック秒、2026-01-01T00:00:00Z 近傍）。 */
export const NOW = 1_767_225_600;

/** base64url（パディングなし）エンコードのショートハンド。 */
export function b64u(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

/** UTF-8 文字列を base64url（パディングなし）エンコードする。 */
export function b64uText(text: string): string {
  return b64u(new TextEncoder().encode(text));
}

/** 非圧縮公開鍵（0x04 || x || y）から JWK の x / y 座標を取り出す。 */
export function uncompressedToXY(pub: Uint8Array): { x: string; y: string } {
  return {
    x: b64u(pub.subarray(1, 33)),
    y: b64u(pub.subarray(33, 65)),
  };
}

/** alg ごとの署名関数（64 バイト raw を返す）と JWK 構築。 */
export interface KeyFixture {
  readonly alg: string;
  readonly crv: string;
  readonly jwk: Record<string, unknown>;
  /**
   * signing-input（UTF-8 バイト列）に署名し 64B raw 署名を返す。
   *
   * `assembleDidJwt` は prehash せず signing-input をそのまま渡すため、ECDSA の SHA-256 は
   * 各フィクスチャ側で適用する（PureEdDSA との契約統一）。
   */
  sign(signingInput: Uint8Array): Uint8Array;
}

/** ES256（P-256）の鍵フィクスチャを既知秘密鍵から作る。 */
export function p256Fixture(privateKey: Uint8Array): KeyFixture {
  const pub = getP256PublicKey(privateKey, false);
  const { x, y } = uncompressedToXY(pub);
  return {
    alg: 'ES256',
    crv: 'P-256',
    jwk: { kty: 'EC', crv: 'P-256', x, y },
    sign: (signingInput) => signP256(sha256(signingInput), privateKey),
  };
}

/** ES256K（secp256k1）の鍵フィクスチャを既知秘密鍵から作る。 */
export function secp256k1Fixture(privateKey: Uint8Array): KeyFixture {
  const pub = getSecp256k1PublicKey(privateKey, false);
  const { x, y } = uncompressedToXY(pub);
  return {
    alg: 'ES256K',
    crv: 'secp256k1',
    jwk: { kty: 'EC', crv: 'secp256k1', x, y },
    // JWS は raw 64 バイト（r||s）。recoverable 署名の先頭 64 バイトを使う。
    sign: (signingInput) =>
      signSecp256k1Recoverable(sha256(signingInput), privateKey).signature.subarray(0, 64),
  };
}

/**
 * 鍵フィクスチャと payload 部品から did:jwt 文字列を構築する。
 *
 * 既定 payload は本番 `createDidJwt` と同じ構造（`verificationMethod` / `authentication` /
 * `assertionMethod`）を使い、組み立て・署名は `assembleDidJwt` に委譲する。`id` / `iss` / `sub`
 * は既定で省略し（`resolveDidJwt` は省略を許容）、必要なケースのみ `payloadOverrides` で明示する。
 * `tamperSignature` は署名を改竄して無効署名を作るための異常系専用フックで、本番 API には無い。
 */
export function buildDidJwt(
  key: KeyFixture,
  options: {
    payloadOverrides?: Record<string, unknown>;
    headerOverrides?: Record<string, unknown>;
    /** 署名対象を改竄して無効署名を作る。 */
    tamperSignature?: boolean;
  } = {},
): string {
  const header = { alg: key.alg, typ: 'JWT', ...options.headerOverrides };
  const payload: Record<string, unknown> = {
    iat: NOW,
    verificationMethod: [
      {
        id: '#key-1',
        type: 'JsonWebKey',
        publicKeyJwk: key.jwk,
      },
    ],
    authentication: ['#key-1'],
    assertionMethod: ['#key-1'],
    ...options.payloadOverrides,
  };
  return assembleDidJwt(header, payload, (signingInput) => {
    let sig = key.sign(signingInput);
    if (options.tamperSignature) {
      sig = sig.slice();
      sig[0] = sig[0] === undefined ? 0 : (sig[0] ^ 0xff) & 0xff;
    }
    return sig;
  });
}
