/**
 * KeyManager の P-256（SLIP-0010）鍵導出と ES256 署名の検証（実鍵・モック禁止）。
 *
 * 検証内容:
 * - `deriveP256Key` が SLIP-0010 の導出結果を返し、同一 seed・同一パスで決定的（ニーモニックだけで復元できる）。
 * - 再導出は登録済みの同一オブジェクトを返す（旧秘密鍵が `zeroize()` の走査から漏れない）。
 * - non-hardened・不正パスは 1040、seed 未設定は 1041。
 * - `getCredentialSigner` が ES256 の署名鍵を返し、署名した JWT-VC が `verifyCredential` で通る。
 * - P-256 鍵は secp256k1 専用の `getSigner` / `signRawDigest` では使えない（1030）。
 * - `zeroize()` 後の P-256 署名鍵は 1004 で失効する。
 * - レガシー secp256k1（BIP-32）の導出結果は変わらない。
 */

import { describe, expect, it } from 'bun:test';
import {
  issueCredential,
  type VerifiableCredential,
  verifyCredential,
} from '../../credential/index.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { deriveSlip10Nist256p1, p256DidPath } from '../derivation/slip10.js';
import { mnemonicToSeed } from '../hd.js';
import { KeyManager } from '../keymanager.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NOW = 1_767_225_600;

function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:km-p256',
  };
}

async function ready(): Promise<KeyManager> {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  return km;
}

async function codeOf(promise: Promise<unknown> | (() => unknown)): Promise<string | undefined> {
  try {
    await (typeof promise === 'function' ? promise() : promise);
  } catch (error) {
    return error instanceof VericertsError ? error.code : undefined;
  }
  return undefined;
}

describe('KeyManager.deriveP256Key', () => {
  it('ニーモニックの seed から SLIP-0010 の結果を返し、同じ入力で決定的に再現する', async () => {
    const km = await ready();
    const path = p256DidPath(0);
    const keyPair = await km.deriveP256Key(path);
    const expected = deriveSlip10Nist256p1(mnemonicToSeed(TEST_MNEMONIC), path);

    expect(keyPair.algorithm).toBe('P-256');
    expect(keyPair.derivationPath).toBe(path);
    expect(keyPair.publicKey).toEqual(expected.publicKey);
    expect(keyPair.privateKey).toEqual(expected.privateKey);

    const restored = await ready();
    expect((await restored.deriveP256Key(path)).publicKey).toEqual(keyPair.publicKey);
    expect((await restored.deriveP256Key(p256DidPath(1))).publicKey).not.toEqual(keyPair.publicKey);
  });

  it('再導出は登録済みの同一オブジェクトを返す', async () => {
    const km = await ready();
    const first = await km.deriveP256Key(p256DidPath(0));
    expect(await km.deriveP256Key(p256DidPath(0))).toBe(first);
  });

  it('non-hardened・不正パスは 1040、seed 未設定は 1041', async () => {
    const km = await ready();
    for (const path of ["m/9256'/0'/0'/0", 'm', "m/9256'/x", '']) {
      expect(await codeOf(km.deriveP256Key(path))).toBe(ErrorCodes.DERIVATION_PATH_INVALID);
    }
    const fresh = new KeyManager();
    expect(await codeOf(fresh.deriveP256Key(p256DidPath(0)))).toBe(
      ErrorCodes.MASTER_SEED_NOT_INITIALIZED,
    );
  });

  it('レガシー secp256k1（BIP-32）のペルソナ鍵は従来どおり導出される', async () => {
    const km = await ready();
    const legacy = await km.deriveKey("m/44'/60'/0'/0/0");
    expect(legacy.algorithm).toBe('secp256k1');
    // Hardhat / Foundry 既定のテストニーモニックの account 0 アドレス。
    expect(legacy.address).toBe('0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
  });
});

describe('P-256 鍵の署名', () => {
  it('getCredentialSigner は ES256 の署名鍵を返し、JWT-VC が verifyCredential で通る', async () => {
    const km = await ready();
    const keyPair = await km.deriveP256Key(p256DidPath(0));
    const signer = km.getCredentialSigner(keyPair.id);

    expect(signer.alg).toBe('ES256');
    expect(signer.publicKeyJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect('privateKey' in signer).toBe(false);

    const jwt = issueCredential(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, {
      key: { publicKeyJwk: signer.publicKeyJwk },
      nowSeconds: NOW,
    });
    expect(result.header.alg).toBe('ES256');
  });

  it('secp256k1 専用の getSigner / signRawDigest は P-256 鍵を 1030 で拒否する', async () => {
    const km = await ready();
    const keyPair = await km.deriveP256Key(p256DidPath(0));
    expect(await codeOf(() => km.getSigner(keyPair.id))).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
    expect(await codeOf(() => km.signRawDigest(keyPair.id, new Uint8Array(32)))).toBe(
      ErrorCodes.UNSUPPORTED_ALGORITHM,
    );
  });

  it('zeroize() 後は旧署名鍵が 1004 で失効し、秘密鍵は消去される', async () => {
    const km = await ready();
    const keyPair = await km.deriveP256Key(p256DidPath(0));
    const signer = km.getCredentialSigner(keyPair.id);
    km.zeroize();

    expect(await codeOf(() => signer.sign(new Uint8Array([1])))).toBe(ErrorCodes.KEY_NOT_FOUND);
    expect(keyPair.privateKey.every((byte) => byte === 0)).toBe(true);
  });
});
