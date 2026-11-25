/**
 * `didDocumentToVerifierKey` のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - did:key(secp256k1 / P-256 / Ed25519) / did:jwk(P-256 / OKP) / did:ethr(publicKeyHex) の
 *   DID Document から正しい JWK を抽出。
 * - 未対応鍵タイプ（RSA JWK / OKP X25519）は UNSUPPORTED_ALGORITHM（1030）。
 * - 公開鍵表現を持たない / id 指定が見つからない場合は DID_DOC_INVALID（2010）。
 * - 抽出した JWK で `issueCredential` → `verifyCredential` ラウンドトリップが通る（実鍵往復）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { DIDDocument } from '../../../identity/did.js';
import { createDidKey } from '../../../identity/method-key.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { issueCredential } from '../issue.js';
import { createPrivateKeySigner } from '../signer.js';
import type { VerifiableCredential } from '../vc.js';
import { didDocumentToVerifierKey } from '../verifier-key.js';
import { verifyCredential } from '../verify.js';

const SECP_KEY = new Uint8Array(32).fill(9);
const P256_KEY = new Uint8Array(32).fill(7);
const ED_KEY = new Uint8Array(32).fill(5);
const NOW = 1_767_225_600;

/** 単一の `publicKeyJwk` VerificationMethod だけを持つ DID Document を組み立てる。 */
function jwkDoc(publicKeyJwk: Record<string, unknown>): DIDDocument {
  const id = 'did:jwk:sample';
  const vmId = `${id}#0`;
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id,
    verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', controller: id, publicKeyJwk }],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
}

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): Record<string, unknown> {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
  };
}

describe('didDocumentToVerifierKey: 公開鍵表現ごとの抽出', () => {
  it('did:key(secp256k1) の publicKeyMultibase から secp256k1 JWK を抽出', () => {
    const compressed = getSecp256k1PublicKey(SECP_KEY, true);
    const doc = createDidKey('secp256k1', compressed);
    const key = didDocumentToVerifierKey(doc);
    const expected = toJwk(getSecp256k1PublicKey(SECP_KEY, false), 'secp256k1');
    expect(key.publicKeyJwk).toEqual(expected);
  });

  it('did:key(P-256) の publicKeyMultibase から P-256 JWK を抽出', () => {
    const compressed = getP256PublicKey(P256_KEY, true);
    const doc = createDidKey('P-256', compressed);
    const key = didDocumentToVerifierKey(doc);
    const expected = toJwk(getP256PublicKey(P256_KEY, false), 'P-256');
    expect(key.publicKeyJwk).toEqual(expected);
  });

  it('did:jwk(P-256) の publicKeyJwk をそのまま使う', () => {
    const jwk = toJwk(getP256PublicKey(P256_KEY, false), 'P-256');
    expect(didDocumentToVerifierKey(jwkDoc(jwk)).publicKeyJwk).toEqual(jwk);
  });

  it('did:key(Ed25519) の publicKeyMultibase から OKP JWK を抽出', () => {
    const publicKey = getEd25519PublicKey(ED_KEY);
    const doc = createDidKey('Ed25519', publicKey);
    expect(didDocumentToVerifierKey(doc).publicKeyJwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(publicKey).toString('base64url'),
    });
  });

  it('OKP（Ed25519）JWK は EdDSA 検証鍵としてそのまま使う', () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' };
    expect(didDocumentToVerifierKey(jwkDoc(jwk)).publicKeyJwk).toEqual(jwk);
  });

  it('did:ethr の publicKeyHex（圧縮 / 0x 付き）から secp256k1 JWK を抽出', () => {
    const compressed = getSecp256k1PublicKey(SECP_KEY, true);
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:ethr:0xabc',
      verificationMethod: [
        {
          id: 'did:ethr:0xabc#controller',
          type: 'EcdsaSecp256k1VerificationKey2019',
          controller: 'did:ethr:0xabc',
          publicKeyHex: `0x${toHex(compressed)}`,
        },
      ],
      authentication: ['did:ethr:0xabc#controller'],
      assertionMethod: ['did:ethr:0xabc#controller'],
    } as const;
    const key = didDocumentToVerifierKey(doc);
    const expected = toJwk(getSecp256k1PublicKey(SECP_KEY, false), 'secp256k1');
    expect(key.publicKeyJwk).toEqual(expected);
  });

  it('did:ethr の publicKeyHex（非圧縮 / 0x なし）からも secp256k1 JWK を抽出', () => {
    const uncompressed = getSecp256k1PublicKey(SECP_KEY, false);
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:ethr:0xabc',
      verificationMethod: [
        {
          id: 'did:ethr:0xabc#controller',
          type: 'EcdsaSecp256k1VerificationKey2019',
          controller: 'did:ethr:0xabc',
          publicKeyHex: toHex(uncompressed),
        },
      ],
      authentication: ['did:ethr:0xabc#controller'],
      assertionMethod: ['did:ethr:0xabc#controller'],
    } as const;
    const key = didDocumentToVerifierKey(doc);
    const expected = toJwk(uncompressed, 'secp256k1');
    expect(key.publicKeyJwk).toEqual(expected);
  });
});

describe('didDocumentToVerifierKey: 選択方針', () => {
  it('opts.verificationMethodId で対象鍵を選ぶ', () => {
    const docP256 = createDidKey('P-256', getP256PublicKey(P256_KEY, true));
    const docSecp = createDidKey('secp256k1', getSecp256k1PublicKey(SECP_KEY, true));
    const vmP256 = docP256.verificationMethod[0];
    const vmSecp = docSecp.verificationMethod[0];
    if (vmP256 === undefined || vmSecp === undefined) {
      throw new Error('fixture');
    }
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:example:multi',
      verificationMethod: [vmP256, vmSecp],
      // assertionMethod 先頭は P-256 だが、id 指定で secp256k1 を選べることを確認する。
      authentication: [vmP256.id],
      assertionMethod: [vmP256.id, vmSecp.id],
    } as const;
    const key = didDocumentToVerifierKey(doc, { verificationMethodId: vmSecp.id });
    expect(key.publicKeyJwk).toEqual(toJwk(getSecp256k1PublicKey(SECP_KEY, false), 'secp256k1'));
  });

  it('id 指定が見つからない場合は DID_DOC_INVALID（2010）', () => {
    const doc = createDidKey('P-256', getP256PublicKey(P256_KEY, true));
    expect(() =>
      didDocumentToVerifierKey(doc, { verificationMethodId: 'did:example:none#0' }),
    ).toThrow(new VericertsError(ErrorCodes.DID_DOC_INVALID));
  });

  it('assertionMethod の埋め込み VerificationMethod を直接使う', () => {
    const jwk = toJwk(getP256PublicKey(P256_KEY, false), 'P-256');
    const embedded = {
      id: 'did:example:embed#0',
      type: 'JsonWebKey2020',
      controller: 'did:example:embed',
      publicKeyJwk: jwk,
    };
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:example:embed',
      verificationMethod: [embedded],
      authentication: ['did:example:embed#0'],
      assertionMethod: [embedded],
    } as const;
    const key = didDocumentToVerifierKey(doc);
    expect(key.publicKeyJwk).toEqual(jwk);
  });
});

describe('didDocumentToVerifierKey: 未対応 / 不正', () => {
  it('RSA JWK は UNSUPPORTED_ALGORITHM（1030）', () => {
    const doc = jwkDoc({ kty: 'RSA', n: 'AAAA', e: 'AQAB' });
    expect(() => didDocumentToVerifierKey(doc)).toThrow(
      new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM),
    );
  });

  it('OKP でも crv が X25519 なら UNSUPPORTED_ALGORITHM（1030）', () => {
    const doc = jwkDoc({ kty: 'OKP', crv: 'X25519', x: 'AAAA' });
    expect(() => didDocumentToVerifierKey(doc)).toThrow(
      new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM),
    );
  });

  it('OKP（Ed25519）JWK に x が無ければ DID_DOC_INVALID（2010）', () => {
    const doc = jwkDoc({ kty: 'OKP', crv: 'Ed25519' });
    expect(() => didDocumentToVerifierKey(doc)).toThrow(
      new VericertsError(ErrorCodes.DID_DOC_INVALID),
    );
  });

  it('公開鍵表現を持たない VerificationMethod は DID_DOC_INVALID（2010）', () => {
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:pkh:eip155',
      verificationMethod: [
        {
          id: 'did:pkh:eip155#blockchain',
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: 'did:pkh:eip155',
          blockchainAccountId: 'eip155:1:0xabc',
        },
      ],
      authentication: ['did:pkh:eip155#blockchain'],
      assertionMethod: ['did:pkh:eip155#blockchain'],
    } as const;
    expect(() => didDocumentToVerifierKey(doc)).toThrow(
      new VericertsError(ErrorCodes.DID_DOC_INVALID),
    );
  });

  it('verificationMethod が空なら DID_DOC_INVALID（2010）', () => {
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:example:empty',
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    } as const;
    expect(() => didDocumentToVerifierKey(doc)).toThrow(
      new VericertsError(ErrorCodes.DID_DOC_INVALID),
    );
  });
});

describe('didDocumentToVerifierKey: 実鍵で verifyCredential 往復', () => {
  it('did:key(secp256k1) から抽出した JWK で ES256K の VC 検証が通る', () => {
    const doc = createDidKey('secp256k1', getSecp256k1PublicKey(SECP_KEY, true));
    const key = didDocumentToVerifierKey(doc);
    const jwt = issueCredential(sampleVc(), createPrivateKeySigner(SECP_KEY, 'ES256K'), {
      nowSeconds: NOW,
    });
    const result = verifyCredential(jwt, { key, nowSeconds: NOW });
    expect(result.payload.iss).toBe('did:example:issuer');
  });

  it('did:jwk(P-256) から抽出した JWK で ES256 の VC 検証が通る', () => {
    const jwk = toJwk(getP256PublicKey(P256_KEY, false), 'P-256');
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:jwk:p256',
      verificationMethod: [
        {
          id: 'did:jwk:p256#0',
          type: 'JsonWebKey2020',
          controller: 'did:jwk:p256',
          publicKeyJwk: jwk,
        },
      ],
      authentication: ['did:jwk:p256#0'],
      assertionMethod: ['did:jwk:p256#0'],
    } as const;
    const key = didDocumentToVerifierKey(doc);
    const jwt = issueCredential(sampleVc(), createPrivateKeySigner(P256_KEY, 'ES256'), {
      nowSeconds: NOW,
    });
    const result = verifyCredential(jwt, { key, nowSeconds: NOW });
    expect(result.payload.iss).toBe('did:example:issuer');
  });

  it('did:ethr(publicKeyHex) から抽出した JWK で ES256K の VC 検証が通る', () => {
    const compressed = getSecp256k1PublicKey(SECP_KEY, true);
    const doc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:ethr:0xabc',
      verificationMethod: [
        {
          id: 'did:ethr:0xabc#controller',
          type: 'EcdsaSecp256k1VerificationKey2019',
          controller: 'did:ethr:0xabc',
          publicKeyHex: `0x${toHex(compressed)}`,
        },
      ],
      authentication: ['did:ethr:0xabc#controller'],
      assertionMethod: ['did:ethr:0xabc#controller'],
    } as const;
    const key = didDocumentToVerifierKey(doc);
    const jwt = issueCredential(sampleVc(), createPrivateKeySigner(SECP_KEY, 'ES256K'), {
      nowSeconds: NOW,
    });
    const result = verifyCredential(jwt, { key, nowSeconds: NOW });
    expect(result.payload.iss).toBe('did:example:issuer');
  });
});
