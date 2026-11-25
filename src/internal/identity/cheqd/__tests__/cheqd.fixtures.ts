/**
 * did:cheqd の単体テスト共通フィクスチャ。
 *
 * `LIVE_*` は 2026-10-21 に `https://resolver.cheqd.net` が返した実際の値（mainnet の登録済み DID）。
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { base58, base64urlnopad } from '@scure/base';

export const RESOLVER_URL = 'https://resolver.cheqd.example.org';

/** 実機で確認した Indy 形式の mainnet DID と、その `Ed25519VerificationKey2020` の公開鍵。 */
export const LIVE_DID = 'did:cheqd:mainnet:Ps1ysXP2Ae6GBfxNhNQNKN';
export const LIVE_KEY_MULTIBASE = 'z6Mkta7joRuvDh7UnoESdgpr9dDUMh5LvdoECDi3WGrJoscA';
export const LIVE_VERSION_ID = '4fa8e367-c70e-533e-babf-3732d9761061';

/** UUID 形式の DID（形式のみ。台帳には存在しない）。 */
export const UUID_DID = 'did:cheqd:testnet:55dbc8bf-fba3-4117-855c-1e0dc1d3bb47';

function ed25519Bytes(seed: number): Uint8Array {
  const secret = new Uint8Array(32);
  secret[31] = seed;
  return ed25519.getPublicKey(secret);
}

/** `Ed25519VerificationKey2018`（`publicKeyBase58`）。 */
export function key2018(did: string, fragment = 'k18', seed = 1): Record<string, unknown> {
  return {
    id: `${did}#${fragment}`,
    type: 'Ed25519VerificationKey2018',
    controller: did,
    publicKeyBase58: base58.encode(ed25519Bytes(seed)),
  };
}

/** `Ed25519VerificationKey2020`（`publicKeyMultibase`、multicodec `0xed01`）。 */
export function key2020(did: string, fragment = 'k20', seed = 2): Record<string, unknown> {
  return {
    id: `${did}#${fragment}`,
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyMultibase: `z${base58.encode(Uint8Array.of(0xed, 0x01, ...ed25519Bytes(seed)))}`,
  };
}

/** `JsonWebKey2020`（OKP / Ed25519 の `publicKeyJwk`）。 */
export function keyJwk(did: string, fragment = 'kjwk', seed = 3): Record<string, unknown> {
  return {
    id: `${did}#${fragment}`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: base64urlnopad.encode(ed25519Bytes(seed)) },
  };
}

/** cheqd リゾルバーの解決結果（`application/ld+json;profile="https://w3id.org/did-resolution"`）。 */
export function resolutionResult(
  did: string,
  overrides: {
    document?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
    resolutionMetadata?: Record<string, unknown>;
  } = {},
): Record<string, unknown> {
  return {
    '@context': 'https://w3id.org/did-resolution/v1',
    didDocument: {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [key2020(did, 'key1')],
      authentication: [`${did}#key1`],
      assertionMethod: [`${did}#key1`],
      ...overrides.document,
    },
    didResolutionMetadata: { contentType: 'application/did', ...overrides.resolutionMetadata },
    didDocumentMetadata: {
      created: '2022-04-05T11:49:19Z',
      versionId: LIVE_VERSION_ID,
      ...overrides.metadata,
    },
  };
}

/** リゾルバーの Content-Type（`profile` つき）。 */
export const RESOLUTION_CONTENT_TYPE =
  'application/ld+json;profile="https://w3id.org/did-resolution"';
