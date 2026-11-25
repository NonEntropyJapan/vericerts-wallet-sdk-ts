/**
 * `didcomm/resolve.ts`（DID Document から keyAgreement 鍵 / serviceEndpoint を抽出）のテスト
 * （詳細フロー 手順 1）。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../errors.js';
import type { Service } from '../../identity/did.js';
import { x25519Key } from '../../identity/peer/__tests__/numalgo2-keys.fixtures.js';
import {
  createDidPeer2,
  encodePublicKeyMultibase,
  resolveDidPeer,
} from '../../identity/peer/method-peer.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../keymanager/signer.js';
import { resolveKeyAgreement, resolveServiceEndpoint } from '../resolve.js';

function buildPeerDoc(services: readonly Service[] = []) {
  const signKey = encodePublicKeyMultibase(
    'secp256k1',
    getSecp256k1PublicKey(new Uint8Array(32).fill(1), true),
  );
  const encKey = encodePublicKeyMultibase(
    'P-256',
    getP256PublicKey(new Uint8Array(32).fill(2), true),
  );
  const did = createDidPeer2({ verificationKeys: [signKey], keyAgreementKeys: [encKey], services });
  return resolveDidPeer(did);
}

describe('resolveKeyAgreement', () => {
  it('did:peer numalgo2 の P-256 keyAgreement 鍵を JWK として抽出する', () => {
    const doc = buildPeerDoc();
    const result = resolveKeyAgreement(doc);
    expect(result.publicKeyJwk.crv).toBe('P-256');
    expect(result.publicKeyJwk.kty).toBe('EC');
    const keyAgreementIds = (doc.keyAgreement ?? []).map((entry) =>
      typeof entry === 'string' ? entry : entry.id,
    );
    expect(keyAgreementIds).toContain(result.id);
  });

  it('keyAgreement が無い DID Document は DIDCOMM_PACKING_FAILED で拒否する', () => {
    const signKey = encodePublicKeyMultibase(
      'secp256k1',
      getSecp256k1PublicKey(new Uint8Array(32).fill(3), true),
    );
    const did = createDidPeer2({ verificationKeys: [signKey], keyAgreementKeys: [], services: [] });
    const doc = resolveDidPeer(did);
    expect(() => resolveKeyAgreement(doc)).toThrow(VericertsError);
    try {
      resolveKeyAgreement(doc);
      expect.unreachable();
    } catch (error) {
      expect((error as VericertsError).code).toBe('9003');
    }
  });

  it('keyAgreement 鍵が P-256 でない（X25519）場合は DIDCOMM_PACKING_FAILED で拒否する', () => {
    const signKey = encodePublicKeyMultibase(
      'secp256k1',
      getSecp256k1PublicKey(new Uint8Array(32).fill(4), true),
    );
    const encKey = x25519Key(5);
    const did = createDidPeer2({
      verificationKeys: [signKey],
      keyAgreementKeys: [encKey],
      services: [],
    });
    const doc = resolveDidPeer(did);
    expect(() => resolveKeyAgreement(doc)).toThrow(VericertsError);
  });
});

describe('resolveServiceEndpoint', () => {
  it('DIDCommMessaging service の serviceEndpoint（文字列）を抽出する', () => {
    const doc = buildPeerDoc([
      { id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: 'https://example.com/didcomm' },
    ]);
    expect(resolveServiceEndpoint(doc)).toBe('https://example.com/didcomm');
  });

  it('serviceEndpoint がオブジェクト形式（uri フィールド）でも抽出する', () => {
    const doc = buildPeerDoc([
      {
        id: '#didcomm',
        type: 'DIDCommMessaging',
        serviceEndpoint: { uri: 'https://mediator.example.com', accept: ['didcomm/v2'] },
      },
    ]);
    expect(resolveServiceEndpoint(doc)).toBe('https://mediator.example.com');
  });

  it('DIDCommMessaging service が無い場合は undefined を返す', () => {
    const doc = buildPeerDoc([]);
    expect(resolveServiceEndpoint(doc)).toBeUndefined();
  });
});
