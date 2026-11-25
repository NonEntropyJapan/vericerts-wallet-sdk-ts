/**
 * did:jwk の create → resolve ラウンドトリップ検証。
 *
 * `@noble/curves` で実鍵を生成し、その公開鍵から JWK を組み立て、createDidJwk →
 * resolveDidJwk で publicKeyJwk が完全に往復することを確認する。
 * EC（P-256 / P-384）・OKP（Ed25519 / X25519）の各鍵タイプをカバーする。
 */

import { describe, expect, it } from 'bun:test';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { p256, p384 } from '@noble/curves/nist.js';
import { base64urlnopad } from '@scure/base';
import type { PublicKeyJwk } from '../../did.js';
import { createDidJwk, resolveDidJwk } from '../method-jwk.js';

/** bigint 座標を固定バイト長の big-endian base64url（パディングなし）へ変換する。 */
function coordToBase64url(value: bigint, byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  let v = value;
  for (let i = byteLength - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return base64urlnopad.encode(bytes);
}

/** EC 鍵（curve）から公開鍵 JWK を生成する。 */
function ecJwk(curve: typeof p256, crv: 'P-256' | 'P-384', byteLength: number): PublicKeyJwk {
  // 秘密鍵長は曲線のフィールド長（P-256=32B / P-384=48B）に合わせる。
  const priv = new Uint8Array(byteLength).fill(11);
  const pub = curve.getPublicKey(priv, false);
  const affine = curve.Point.fromBytes(pub).toAffine();
  return {
    kty: 'EC',
    crv,
    x: coordToBase64url(affine.x, byteLength),
    y: coordToBase64url(affine.y, byteLength),
  };
}

/** OKP 鍵から公開鍵 JWK を生成する。 */
function okpJwk(pub: Uint8Array, crv: 'Ed25519' | 'X25519'): PublicKeyJwk {
  return { kty: 'OKP', crv, x: base64urlnopad.encode(pub) };
}

const cases: ReadonlyArray<{ readonly name: string; readonly jwk: PublicKeyJwk }> = [
  { name: 'EC P-256', jwk: ecJwk(p256, 'P-256', 32) },
  { name: 'EC P-384', jwk: ecJwk(p384 as unknown as typeof p256, 'P-384', 48) },
  {
    name: 'OKP Ed25519',
    jwk: okpJwk(ed25519.getPublicKey(new Uint8Array(32).fill(12)), 'Ed25519'),
  },
  { name: 'OKP X25519', jwk: okpJwk(x25519.getPublicKey(new Uint8Array(32).fill(13)), 'X25519') },
];

describe('createDidJwk → resolveDidJwk roundtrip', () => {
  for (const { name, jwk } of cases) {
    it(`${name}: JWK が往復で完全一致する`, () => {
      const created = createDidJwk(jwk);
      const resolved = resolveDidJwk(created.id);

      expect(resolved.id).toBe(created.id);
      expect(resolved.verificationMethod[0]?.publicKeyJwk).toEqual(jwk);
      expect(resolved.verificationMethod[0]?.type).toBe('JsonWebKey2020');
      // create と resolve の DID Document が一致する（relationship 含む）。
      expect(resolved).toEqual(created);
    });
  }
});
