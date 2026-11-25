/**
 * did-resolve カテゴリのコンフォーマンスベクタ（did:jwk のみ）。
 *
 * did:jwk はネットワーク不要な純粋関数なので対象にする。did:web / did:ethr は
 * ネットワーク/RPCフィクスチャが別途要るためこのカテゴリでは扱わない。
 */

import type { PublicKeyJwk } from '../../src/internal/identity/did.js';
import { createDidJwk, resolveDidJwk } from '../../src/internal/identity/jwk/method-jwk.js';
import { getEd25519PublicKey } from '../../src/internal/keymanager/ed25519.js';
import { getP256PublicKey } from '../../src/internal/keymanager/signer.js';
import { b64url, type Case, errorCodeOf } from './shared.js';

export function getDidResolveCases(): Case[] {
  const cases: Case[] = [];

  const p256Priv = new Uint8Array(32).fill(11);
  const p256PubUncompressed = getP256PublicKey(p256Priv, false);
  const p256Jwk: PublicKeyJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: b64url(p256PubUncompressed.subarray(1, 33)),
    y: b64url(p256PubUncompressed.subarray(33, 65)),
  };

  const edPriv = new Uint8Array(32).fill(13);
  const edPub = getEd25519PublicKey(edPriv);
  const edJwk: PublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(edPub) };

  for (const [label, jwk] of [
    ['P-256', p256Jwk],
    ['Ed25519', edJwk],
  ] as const) {
    const doc = createDidJwk(jwk);
    cases.push({
      id: `did-jwk-create-resolve-roundtrip-${label}`,
      category: 'did-resolve',
      description: `did:jwk create+resolve roundtrip (${label})`,
      input: { did: doc.id },
      expected: { ok: true, document: doc },
    });
  }

  cases.push({
    id: 'did-jwk-invalid-prefix',
    category: 'did-resolve',
    description: 'did:jwk resolve rejects a non-did:jwk string',
    input: { did: 'did:web:example.com' },
    expected: { ok: false, errorCode: errorCodeOf(() => resolveDidJwk('did:web:example.com')) },
  });

  cases.push({
    id: 'did-jwk-invalid-base64url',
    category: 'did-resolve',
    description: 'did:jwk resolve rejects invalid base64url payload',
    input: { did: 'did:jwk:not-valid-base64url!!!' },
    expected: {
      ok: false,
      errorCode: errorCodeOf(() => resolveDidJwk('did:jwk:not-valid-base64url!!!')),
    },
  });

  return cases;
}
