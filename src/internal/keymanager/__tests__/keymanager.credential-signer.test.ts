/**
 * KeyManager.getCredentialSigner の振る舞い検証（実鍵・モック禁止）。
 *
 * 検証内容:
 * - getCredentialSigner で署名した JWT-VC が credential.verifyCredential で検証成功（鍵非露出のまま発行）。
 * - 返り値に privateKey が一切含まれない（alg / publicKeyJwk / sign のみ）。
 * - 公開鍵 JWK が KeyPair の secp256k1 公開鍵と座標一致する。
 * - 未登録 keyId は KEY_NOT_FOUND（1004）。
 *
 * keymanager（Foundation）は credential を import しないが、本テストは両層の結合
 * （構造的互換による橋渡し）を検証するため credential を利用する。
 */

import { describe, expect, it } from 'bun:test';
import {
  issueCredential,
  type VerifiableCredential,
  verifyCredential,
} from '../../credential/index.js';
import { VericertsError } from '../../errors.js';
import { KeyManager } from '../keymanager.js';
import { getSecp256k1PublicKey } from '../signer.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ETH_PATH = "m/44'/60'/0'/0/0";

/** 固定現在時刻（2026-01-01T00:00:00Z 近傍）。 */
const NOW = 1_767_225_600;

/** import + derive 済みの KeyManager と KeyPair を用意する。 */
async function setup() {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  const keyPair = await km.deriveKey(ETH_PATH);
  return { km, keyPair };
}

/** サンプル VC を作る。 */
function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:km-signer',
  };
}

describe('KeyManager.getCredentialSigner', () => {
  it('署名した JWT-VC が verifyCredential で検証成功する（鍵非露出のまま発行）', async () => {
    const { km, keyPair } = await setup();
    const signer = km.getCredentialSigner(keyPair.id);

    const jwt = issueCredential(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, {
      key: { publicKeyJwk: signer.publicKeyJwk },
      nowSeconds: NOW,
    });

    expect(result.header.alg).toBe('ES256K');
    expect(result.payload.iss).toBe('did:example:issuer');
    expect(result.payload.jti).toBe('urn:uuid:km-signer');
  });

  it('返り値に privateKey が含まれない（alg / publicKeyJwk / sign のみ）', async () => {
    const { km, keyPair } = await setup();
    const signer = km.getCredentialSigner(keyPair.id);
    expect(Object.keys(signer).sort()).toEqual(['alg', 'publicKeyJwk', 'sign']);
  });

  it('publicKeyJwk が KeyPair の secp256k1 公開鍵座標と一致する', async () => {
    const { km, keyPair } = await setup();
    const signer = km.getCredentialSigner(keyPair.id);

    // KeyPair から直接導出した非圧縮公開鍵で同じ JWK を再構築し、座標一致を確認する。
    const uncompressed = getSecp256k1PublicKey(keyPair.privateKey, false);
    const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
    const jwk = signer.publicKeyJwk as Record<string, unknown>;
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('secp256k1');
    expect(jwk.x).toBe(b64u(uncompressed.subarray(1, 33)));
    expect(jwk.y).toBe(b64u(uncompressed.subarray(33, 65)));
  });

  it('未登録 keyId は KEY_NOT_FOUND（1004）', async () => {
    const { km } = await setup();
    expect(() => km.getCredentialSigner('deadbeef')).toThrow(VericertsError);
    try {
      km.getCredentialSigner('deadbeef');
    } catch (error) {
      expect((error as VericertsError).code).toBe('1004');
    }
  });
});
