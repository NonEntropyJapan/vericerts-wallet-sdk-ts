/**
 * createDidJwk の DID 文字列・DID Document 構築検証。
 *
 * 各鍵タイプ（EC P-256 / P-384 / OKP Ed25519 / X25519）について、
 * - DID が `did:jwk:` プレフィックスを持ち base64url(JWK) で構成されること
 * - VerificationMethod が `#0` / JsonWebKey2020 / publicKeyJwk を持つこと
 * - verification relationship が用途に応じて付与されること
 * を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import type { PublicKeyJwk } from '../../did.js';
import { createDidJwk } from '../method-jwk.js';

/** 既知の公開鍵 JWK サンプル（W3C did:jwk 仕様の例ベース）。 */
const P256_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0',
  y: '_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE',
};
const P384_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-384',
  x: 'lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc',
  y: 'y6N1Icg3If-9DBJVcD-zsKMV-i-i_8d2dgsOdSpgkx9XGZbZuglt0tj-vWN1QM6I',
};
const ED25519_JWK: PublicKeyJwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
};
const X25519_JWK: PublicKeyJwk = {
  kty: 'OKP',
  crv: 'X25519',
  x: '3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08',
};

describe('createDidJwk', () => {
  it('DID は did:jwk: プレフィックスを持ち base64url(JWK) で構成される', () => {
    const doc = createDidJwk(P256_JWK);
    expect(doc.id.startsWith('did:jwk:')).toBe(true);

    const encoded = doc.id.slice('did:jwk:'.length);
    const json = new TextDecoder().decode(base64urlnopad.decode(encoded));
    expect(JSON.parse(json)).toEqual(P256_JWK);
  });

  it('VerificationMethod は #0 / JsonWebKey2020 / publicKeyJwk を持つ', () => {
    const doc = createDidJwk(P256_JWK);
    const vm = doc.verificationMethod[0];
    expect(vm?.id).toBe(`${doc.id}#0`);
    expect(vm?.type).toBe('JsonWebKey2020');
    expect(vm?.controller).toBe(doc.id);
    expect(vm?.publicKeyJwk).toEqual(P256_JWK);
  });

  it('@context は did/v1 と jws-2020/v1 を含む', () => {
    const doc = createDidJwk(ED25519_JWK);
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
    expect(doc['@context']).toContain('https://w3id.org/security/suites/jws-2020/v1');
  });

  it('EC P-256: 署名と鍵交換の両方の relationship を持つ', () => {
    const doc = createDidJwk(P256_JWK);
    const ref = `${doc.id}#0`;
    expect(doc.authentication).toEqual([ref]);
    expect(doc.assertionMethod).toEqual([ref]);
    expect(doc.capabilityInvocation).toEqual([ref]);
    expect(doc.capabilityDelegation).toEqual([ref]);
    expect(doc.keyAgreement).toEqual([ref]);
  });

  it('EC P-384: 署名と鍵交換の両方の relationship を持つ', () => {
    const doc = createDidJwk(P384_JWK);
    const ref = `${doc.id}#0`;
    expect(doc.authentication).toEqual([ref]);
    expect(doc.keyAgreement).toEqual([ref]);
  });

  it('OKP Ed25519: 署名 relationship のみで keyAgreement を持たない', () => {
    const doc = createDidJwk(ED25519_JWK);
    const ref = `${doc.id}#0`;
    expect(doc.authentication).toEqual([ref]);
    expect(doc.assertionMethod).toEqual([ref]);
    expect(doc.capabilityInvocation).toEqual([ref]);
    expect(doc.capabilityDelegation).toEqual([ref]);
    expect(doc.keyAgreement).toBeUndefined();
  });

  it('OKP X25519: keyAgreement のみで署名 relationship を持たない', () => {
    const doc = createDidJwk(X25519_JWK);
    const ref = `${doc.id}#0`;
    expect(doc.keyAgreement).toEqual([ref]);
    expect(doc.authentication).toEqual([]);
    expect(doc.assertionMethod).toEqual([]);
    expect(doc.capabilityInvocation).toBeUndefined();
    expect(doc.capabilityDelegation).toBeUndefined();
  });

  it('use=sig の EC は keyAgreement を持たない', () => {
    const doc = createDidJwk({ ...P256_JWK, use: 'sig' });
    expect(doc.authentication.length).toBe(1);
    expect(doc.keyAgreement).toBeUndefined();
  });

  it('use=enc の EC は署名 relationship を持たず keyAgreement のみ', () => {
    const doc = createDidJwk({ ...P256_JWK, use: 'enc' });
    expect(doc.authentication).toEqual([]);
    expect(doc.assertionMethod).toEqual([]);
    expect(doc.keyAgreement?.length).toBe(1);
  });
});
