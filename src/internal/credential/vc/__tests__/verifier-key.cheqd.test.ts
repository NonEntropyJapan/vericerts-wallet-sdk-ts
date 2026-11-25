import { describe, expect, it, spyOn } from 'bun:test';
import { base58, base64urlnopad } from '@scure/base';
import { ErrorCodes } from '../../../errors.js';
import {
  expectThrows,
  recordingFetch,
} from '../../../identity/__tests__/network-method.fixtures.js';
import { LIVE_DID, resolutionResult } from '../../../identity/cheqd/__tests__/cheqd.fixtures.js';
import { resolveDidCheqd } from '../../../identity/cheqd/method-cheqd.js';
import type { VerificationMethod } from '../../../identity/did.js';
import { getEd25519PublicKey } from '../../../keymanager/ed25519.js';
import { issueCredential } from '../issue.js';
import { createPrivateKeySigner } from '../signer.js';
import { didDocumentToVerifierKey } from '../verifier-key.js';
import { verificationMethodToJwk } from '../verifier-key-jwk.js';
import { verifyCredential } from '../verify.js';

const PRIVATE_KEY = new Uint8Array(32).fill(5);
const PUBLIC_KEY = getEd25519PublicKey(PRIVATE_KEY);
const VM: VerificationMethod = {
  id: `${LIVE_DID}#key1`,
  type: 'Ed25519VerificationKey2018',
  controller: LIVE_DID,
  publicKeyBase58: base58.encode(PUBLIC_KEY),
};

describe('cheqd Ed25519VerificationKey2018 verifier key', () => {
  it('解決した base58 鍵で実際の EdDSA VC 署名を検証する', async () => {
    const { fetchFn } = recordingFetch(() => ({
      body: JSON.stringify(resolutionResult(LIVE_DID, { document: { verificationMethod: [VM] } })),
    }));
    const { document } = await resolveDidCheqd(LIVE_DID, { fetchFn });
    const key = didDocumentToVerifierKey(document);
    expect(key.publicKeyJwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64urlnopad.encode(PUBLIC_KEY),
    });
    const nowSeconds = 1_767_225_600;
    const vc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: LIVE_DID,
      credentialSubject: { id: 'did:example:subject' },
      issuanceDate: '2025-12-01T00:00:00Z',
      expirationDate: '2027-01-01T00:00:00Z',
    };
    const jwt = issueCredential(vc, createPrivateKeySigner(PRIVATE_KEY, 'EdDSA'), { nowSeconds });
    expect(verifyCredential(jwt, { key, nowSeconds }).payload.iss).toBe(LIVE_DID);
  });

  it('欠落・不正な文字・長さ・型・未対応の VM type を 2010 にする', () => {
    const invalid: unknown[] = [
      undefined,
      null,
      7,
      '',
      '0OIl',
      'abc',
      base58.encode(new Uint8Array(33)),
    ];
    for (const publicKeyBase58 of invalid) {
      expectThrows(
        () => verificationMethodToJwk({ ...VM, publicKeyBase58 } as VerificationMethod),
        ErrorCodes.DID_DOC_INVALID,
      );
    }
    expectThrows(
      () => verificationMethodToJwk({ ...VM, type: 'EcdsaSecp256k1VerificationKey2019' }),
      ErrorCodes.DID_DOC_INVALID,
    );
  });

  it('継承した公開鍵・type を検証鍵として使わない', () => {
    const inheritedKey = Object.assign(Object.create({ publicKeyBase58: VM.publicKeyBase58 }), {
      id: VM.id,
      controller: LIVE_DID,
      type: VM.type,
    });
    const inheritedType = Object.assign(Object.create({ type: VM.type }), {
      id: VM.id,
      controller: LIVE_DID,
      publicKeyBase58: VM.publicKeyBase58,
    });
    for (const vm of [inheritedKey, inheritedType]) {
      expectThrows(() => verificationMethodToJwk(vm), ErrorCodes.DID_DOC_INVALID);
    }
  });

  it('長大な base58 はデコード前に拒否する', () => {
    let calls = 0;
    const decode = spyOn(base58, 'decode').mockImplementation(() => {
      calls++;
      throw new Error('decoder must not run');
    });
    try {
      expectThrows(
        () => verificationMethodToJwk({ ...VM, publicKeyBase58: 'Z'.repeat(100_000) }),
        ErrorCodes.DID_DOC_INVALID,
      );
      expect(calls).toBe(0);
    } finally {
      decode.mockRestore();
    }
  });
});
