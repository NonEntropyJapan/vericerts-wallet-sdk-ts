/**
 * JWT-VP ラウンドトリップテストの共有フィクスチャ（実鍵・モック禁止）。
 *
 * `presentation.roundtrip.test.ts` から分離した固定鍵・公開鍵 JWK・検証関数・サンプル VP
 * （1 ファイル 300 行以下のため）。
 */

import type { PublicKeyJwk } from '../../../identity/did.js';
import { getEd25519PublicKey, verifyEd25519 } from '../../../keymanager/ed25519.js';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  verifyP256,
  verifySecp256k1,
} from '../../../keymanager/signer.js';
import type { CredentialAlg } from '../../vc/jws.js';
import { type CredentialSigner, createPrivateKeySigner } from '../../vc/signer.js';
import { VC_V2_CONTEXT, type VerifiablePresentation } from '../vp.js';

export const P256_KEY = new Uint8Array(32).fill(11);
const SECP_KEY = new Uint8Array(32).fill(13);
const ED_KEY = new Uint8Array(32).fill(15);

/** 非圧縮公開鍵から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** Ed25519 公開鍵（32B）から OKP 公開鍵 JWK を構築する（`y` は持たない）。 */
function toOkpJwk(pub: Uint8Array): PublicKeyJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pub).toString('base64url') };
}

export const FIXTURES: Record<
  CredentialAlg,
  {
    readonly privateKey: Uint8Array;
    readonly jwk: PublicKeyJwk;
    readonly verify: (
      digest: Uint8Array,
      signature: Uint8Array,
      signingInput: Uint8Array,
    ) => boolean;
  }
> = {
  ES256: {
    privateKey: P256_KEY,
    jwk: toJwk(getP256PublicKey(P256_KEY, false), 'P-256'),
    verify: (digest, signature) => verifyP256(digest, signature, getP256PublicKey(P256_KEY, false)),
  },
  ES256K: {
    privateKey: SECP_KEY,
    jwk: toJwk(getSecp256k1PublicKey(SECP_KEY, false), 'secp256k1'),
    verify: (digest, signature) =>
      verifySecp256k1(digest, signature, getSecp256k1PublicKey(SECP_KEY, false)),
  },
  EdDSA: {
    privateKey: ED_KEY,
    jwk: toOkpJwk(getEd25519PublicKey(ED_KEY)),
    // Ed25519 は digest ではなく signing-input を検証する。
    verify: (_digest, signature, signingInput) =>
      verifyEd25519(signingInput, signature, getEd25519PublicKey(ED_KEY)),
  },
};

/** alg ごとの `CredentialSigner`（生 privateKey 由来）。 */
export function signerFor(alg: CredentialAlg): CredentialSigner {
  return createPrivateKeySigner(FIXTURES[alg].privateKey, alg);
}

export function sampleVp(overrides: Partial<VerifiablePresentation> = {}): VerifiablePresentation {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: 'did:example:holder',
    verifiableCredential: ['eyJhbGciOiJFUzI1NiJ9.vc-payload.sig'],
    id: 'urn:uuid:vp-1',
    ...overrides,
  };
}
