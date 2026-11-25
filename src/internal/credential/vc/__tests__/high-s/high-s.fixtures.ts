/**
 * ES256 high-S 受理 / ES256K low-S 限定の回帰テスト用フィクスチャ（実鍵・モック禁止）。
 *
 * 既知の正規（low-S）署名の `s` を `n - s` へ置き換えて、同一鍵・同一 digest に対して有効な
 * high-S 署名を作る（ECDSA では `(r, s)` と `(r, n - s)` はどちらも有効）。
 */

import { expect } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../../keymanager/signer.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../signer.js';

/** high-S の対象 alg（EdDSA は s の正準性を持たないため対象外）。 */
export type EcdsaAlg = 'ES256' | 'ES256K';

/** alg ごとの固定鍵・公開鍵 JWK・署名器・`@noble` 実装。 */
export interface HighSFixture {
  readonly alg: EcdsaAlg;
  readonly crv: 'P-256' | 'secp256k1';
  readonly jwk: PublicKeyJwk;
  readonly signer: CredentialSigner;
  readonly ec: typeof secp256k1;
}

function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const P256_KEY = new Uint8Array(32).fill(51);
const SECP_KEY = new Uint8Array(32).fill(53);

/** ES256 / ES256K の固定フィクスチャ。 */
export const HIGH_S_FIXTURES: Readonly<Record<EcdsaAlg, HighSFixture>> = {
  ES256: {
    alg: 'ES256',
    crv: 'P-256',
    jwk: toJwk(getP256PublicKey(P256_KEY, false), 'P-256'),
    signer: createPrivateKeySigner(P256_KEY, 'ES256'),
    ec: p256 as unknown as typeof secp256k1,
  },
  ES256K: {
    alg: 'ES256K',
    crv: 'secp256k1',
    jwk: toJwk(getSecp256k1PublicKey(SECP_KEY, false), 'secp256k1'),
    signer: createPrivateKeySigner(SECP_KEY, 'ES256K'),
    ec: secp256k1,
  },
};

/** 64B raw 署名の `s` を `n - s` に置き換える（low-S ↔ high-S の反転）。 */
export function flipS(alg: EcdsaAlg, raw: Uint8Array): Uint8Array {
  const { ec } = HIGH_S_FIXTURES[alg];
  const sig = ec.Signature.fromBytes(raw, 'compact');
  return new ec.Signature(sig.r, ec.Point.Fn.ORDER - sig.s).toBytes('compact');
}

/** 署名が high-S か（`s > n/2`）。 */
export function hasHighS(alg: EcdsaAlg, raw: Uint8Array): boolean {
  return HIGH_S_FIXTURES[alg].ec.Signature.fromBytes(raw, 'compact').hasHighS();
}

/** コンパクト JWS（`h.p.s`）の署名セグメントだけを差し替える。 */
export function withSignature(jws: string, signature: Uint8Array): string {
  const [header, payload] = jws.split('.');
  return `${header}.${payload}.${Buffer.from(signature).toString('base64url')}`;
}

/**
 * 正規（low-S）の JWS を high-S 署名へ書き換える。前提（元が low-S・結果が high-S）を固定する。
 *
 * @param alg 署名 alg。
 * @param jws `h.p.s` 形式のコンパクト JWS（署名は low-S であること）。
 */
export function toHighS(alg: EcdsaAlg, jws: string): string {
  const raw = new Uint8Array(Buffer.from(jws.split('.')[2] ?? '', 'base64url'));
  expect(hasHighS(alg, raw)).toBe(false);
  const flipped = flipS(alg, raw);
  expect(hasHighS(alg, flipped)).toBe(true);
  return withSignature(jws, flipped);
}
