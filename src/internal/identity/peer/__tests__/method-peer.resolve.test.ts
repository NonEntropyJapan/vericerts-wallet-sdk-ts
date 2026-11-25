/**
 * did:peer numalgo 0 / 2 / 4 の解決 + DID Document スナップショットテスト
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import type { Service } from '../../did.js';
import {
  createDidPeer0,
  createDidPeer2,
  createDidPeer4,
  encodePublicKeyMultibase,
  resolveDidPeer,
} from '../method-peer.js';
import { p256Key } from './numalgo2-keys.fixtures.js';

const SIGN_KEY = encodePublicKeyMultibase(
  'secp256k1',
  getSecp256k1PublicKey(new Uint8Array(32).fill(5), true),
);
const ENC_KEY = p256Key(6);

describe('resolveDidPeer numalgo 0', () => {
  it('inception 鍵から DID Document を構築する（スナップショット）', () => {
    const did = createDidPeer0(SIGN_KEY);
    const doc = resolveDidPeer(did);
    expect(doc).toEqual({
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [
        {
          id: `${did}#${SIGN_KEY}`,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: SIGN_KEY,
        },
      ],
      authentication: [`${did}#${SIGN_KEY}`],
      assertionMethod: [`${did}#${SIGN_KEY}`],
    });
  });
});

describe('resolveDidPeer numalgo 2', () => {
  it('V/E/S を verificationMethod/keyAgreement/service へ展開する（スナップショット）', () => {
    const service: Service = {
      id: '#dm',
      type: 'DIDCommMessaging',
      serviceEndpoint: {
        uri: 'https://mediator.example.com',
        accept: ['didcomm/v2'],
        routingKeys: ['did:key:z6MkExample'],
      },
    };
    const did = createDidPeer2({
      verificationKeys: [SIGN_KEY],
      keyAgreementKeys: [ENC_KEY],
      services: [service],
    });
    const doc = resolveDidPeer(did);

    expect(doc.id).toBe(did);
    expect(doc.verificationMethod).toEqual([
      { id: `${did}#key-1`, type: 'Multikey', controller: did, publicKeyMultibase: SIGN_KEY },
      { id: `${did}#key-2`, type: 'Multikey', controller: did, publicKeyMultibase: ENC_KEY },
    ]);
    expect(doc.authentication).toEqual([`${did}#key-1`]);
    expect(doc.assertionMethod).toEqual([`${did}#key-1`]);
    expect(doc.keyAgreement).toEqual([`${did}#key-2`]);
    // service の id は省略形に含めないため解決時に #service が再付与され、
    // type は省略形 `dm` から DIDCommMessaging に展開される（peer-did-method-spec）。
    expect(doc.service).toEqual([
      {
        id: `${did}#service`,
        type: 'DIDCommMessaging',
        serviceEndpoint: {
          uri: 'https://mediator.example.com',
          accept: ['didcomm/v2'],
          routingKeys: ['did:key:z6MkExample'],
        },
      },
    ]);
  });

  it('id 無しサービスには #service / #service-1 を付与する', () => {
    const s1: Service = { id: '', type: 'DIDCommMessaging', serviceEndpoint: 'https://a.example' };
    const s2: Service = { id: '', type: 'Other', serviceEndpoint: 'https://b.example' };
    // id を省略形に含めないため、空 id は解決時に再付与される。
    const did = createDidPeer2({ verificationKeys: [SIGN_KEY], services: [s1, s2] });
    const doc = resolveDidPeer(did);
    expect(doc.service?.[0]?.id).toBe(`${did}#service`);
    expect(doc.service?.[1]?.id).toBe(`${did}#service-1`);
    expect(doc.service?.[1]?.type).toBe('Other');
  });
});

describe('resolveDidPeer numalgo 4', () => {
  it('ハッシュ検証 + ドキュメントデコードで id / alsoKnownAs を設定する', () => {
    const document = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-1', type: 'Multikey', controller: '', publicKeyMultibase: SIGN_KEY },
      ],
      authentication: ['#key-1'],
      assertionMethod: ['#key-1'],
    };
    const did = createDidPeer4(document);
    const doc = resolveDidPeer(did);

    const hash = did.slice('did:peer:4'.length).split(':')[0];
    expect(doc.id).toBe(did);
    expect(doc.alsoKnownAs).toEqual([`did:peer:4${hash}`]);
    expect(doc.verificationMethod).toEqual(document.verificationMethod);
    expect(doc.authentication).toEqual(document.authentication);
  });

  it('ハッシュ改ざんは INVALID_DID', () => {
    const document = {
      '@context': ['x'],
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    };
    const did = createDidPeer4(document);
    const encoded = did.slice('did:peer:4'.length).split(':')[1];
    const tampered = `did:peer:4zInvalidHash:${encoded}`;
    expect(() => resolveDidPeer(tampered)).toThrow(VericertsError);
    try {
      resolveDidPeer(tampered);
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });
});
