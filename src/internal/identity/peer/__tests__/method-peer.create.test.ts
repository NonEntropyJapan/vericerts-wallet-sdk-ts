/**
 * did:peer numalgo 0 / 2 / 4 の生成テスト。
 *
 * 公開鍵から実際に DID 文字列を組み立て、numalgo 別の形式・要素を検証する。
 */

import { describe, expect, it } from 'bun:test';
import { getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import type { Service } from '../../did.js';
import {
  createDidPeer0,
  createDidPeer2,
  createDidPeer4,
  encodePublicKeyMultibase,
} from '../method-peer.js';
import { p256Key } from './numalgo2-keys.fixtures.js';

/** Ed25519 風の固定 32B 鍵（生成専用の形式検証用）。 */
const ED25519_KEY = encodePublicKeyMultibase('Ed25519', new Uint8Array(32).fill(7));
/** secp256k1 圧縮 33B 鍵（既知秘密鍵から導出）。 */
const SECP_KEY = encodePublicKeyMultibase(
  'secp256k1',
  getSecp256k1PublicKey(new Uint8Array(32).fill(3), true),
);
/** 暗号鍵（`.E`）として使う P-256 鍵（`E` は P-256 / X25519 のみ。numalgo2-keys.ts 参照）。 */
const ENCRYPTION_KEY = p256Key(8);

describe('createDidPeer0', () => {
  it('numalgo 0 の DID を生成する', () => {
    const did = createDidPeer0(ED25519_KEY);
    expect(did).toBe(`did:peer:0${ED25519_KEY}`);
  });

  it('multibase 不正な鍵は INVALID_DID', () => {
    expect(() => createDidPeer0('Qabc')).toThrow();
  });
});

describe('createDidPeer2', () => {
  it('V のみで生成する', () => {
    const did = createDidPeer2({ verificationKeys: [SECP_KEY] });
    expect(did).toBe(`did:peer:2.V${SECP_KEY}`);
  });

  it('V / E / S を連結して生成する', () => {
    const service: Service = {
      id: '#dm',
      type: 'DIDCommMessaging',
      serviceEndpoint: { uri: 'https://mediator.example.com', accept: ['didcomm/v2'] },
    };
    const did = createDidPeer2({
      verificationKeys: [SECP_KEY],
      keyAgreementKeys: [ENCRYPTION_KEY],
      services: [service],
    });
    expect(did.startsWith(`did:peer:2.V${SECP_KEY}.E${ENCRYPTION_KEY}.S`)).toBe(true);
  });

  it('verificationKeys が空なら INVALID_DID', () => {
    expect(() => createDidPeer2({ verificationKeys: [] })).toThrow();
  });
});

describe('createDidPeer4', () => {
  it('numalgo 4 の長形式 DID を生成する（hash:encodedDocument）', () => {
    const document = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-1', type: 'Multikey', controller: '', publicKeyMultibase: SECP_KEY },
      ],
      authentication: ['#key-1'],
      assertionMethod: ['#key-1'],
    };
    const did = createDidPeer4(document);
    expect(did.startsWith('did:peer:4z')).toBe(true);
    // hash と encodedDocument が ':' で区切られ、両方とも multibase(z) になる。
    const rest = did.slice('did:peer:4'.length);
    const [hash, encoded] = rest.split(':');
    expect(hash?.startsWith('z')).toBe(true);
    expect(encoded?.startsWith('z')).toBe(true);
  });

  it('同一ドキュメントは決定論的に同じ DID を生成する', () => {
    const document = {
      '@context': ['x'],
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    };
    expect(createDidPeer4(document)).toBe(createDidPeer4(document));
  });
});
