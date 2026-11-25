/**
 * did:cheqd の DID 形式と検証鍵の検査。
 */

import { describe, expect, it, spyOn } from 'bun:test';
import { base58 } from '@scure/base';
import { ErrorCodes } from '../../../errors.js';
import {
  ed25519Jwk,
  expectThrows,
  p256Jwk,
  secp256k1Jwk,
} from '../../__tests__/network-method.fixtures.js';
import type { VerificationMethod } from '../../did.js';
import { assertEd25519VerificationMethod, parseDidCheqd } from '../did-cheqd.js';
import {
  key2018,
  key2020,
  keyJwk,
  LIVE_DID,
  LIVE_KEY_MULTIBASE,
  UUID_DID,
} from './cheqd.fixtures.js';

describe('parseDidCheqd', () => {
  it('UUID 形式と Indy 形式（実機の DID）を受理する', () => {
    expect(parseDidCheqd(UUID_DID)).toEqual({
      namespace: 'testnet',
      identifier: '55dbc8bf-fba3-4117-855c-1e0dc1d3bb47',
      style: 'uuid',
    });
    expect(parseDidCheqd(LIVE_DID)).toEqual({
      namespace: 'mainnet',
      identifier: 'Ps1ysXP2Ae6GBfxNhNQNKN',
      style: 'indy',
    });
    expect(parseDidCheqd('did:cheqd:testnet:TAwT8WVt3dz2DBAifwuSkn').style).toBe('indy');
  });

  it('名前空間の省略は 2001 cheqd_namespace_required', () => {
    expectThrows(
      () => parseDidCheqd('did:cheqd:Ps1ysXP2Ae6GBfxNhNQNKN'),
      ErrorCodes.INVALID_DID,
      'cheqd_namespace_required',
    );
    expectThrows(
      () => parseDidCheqd('did:cheqd:55dbc8bf-fba3-4117-855c-1e0dc1d3bb47'),
      ErrorCodes.INVALID_DID,
      'cheqd_namespace_required',
    );
  });

  it('接頭辞・名前空間・識別子の形式不正は 2001 cheqd_invalid_did', () => {
    for (const bad of [
      'did:web:example.com',
      'did:cheqd:',
      'did:cheqd:mainnet:',
      'did:cheqd::Ps1ysXP2Ae6GBfxNhNQNKN',
      'did:cheqd:main-net:Ps1ysXP2Ae6GBfxNhNQNKN',
      'did:cheqd:mainnet:Ps1ysXP2Ae6GBfxNhNQNKN:extra',
      'did:cheqd:mainnet:short',
      'did:cheqd:mainnet:Ps1ysXP2Ae6GBfxNhNQNKNPs1ysX',
      'did:cheqd:mainnet:0s1ysXP2Ae6GBfxNhNQNKN',
      'did:cheqd:mainnet:55dbc8bf-fba3-4117-855c-1e0dc1d3bb4',
      'did:cheqd:mainnet:55dbc8bf-fba3-4117-855c-1e0dc1d3bb4g',
      `did:cheqd:mainnet:${'a'.repeat(3000)}`,
    ]) {
      expectThrows(() => parseDidCheqd(bad), ErrorCodes.INVALID_DID, 'cheqd_invalid_did');
    }
  });
});

describe('assertEd25519VerificationMethod', () => {
  const did = LIVE_DID;
  const asVm = (value: unknown) => value as VerificationMethod;

  it('複数の公開鍵表現を持つ VM は優先順位による鍵の取り違えを防ぐため拒否する', () => {
    for (const vm of [
      { ...key2018(did), publicKeyJwk: p256Jwk() },
      { ...key2020(did), publicKeyJwk: p256Jwk() },
      { ...keyJwk(did), publicKeyMultibase: key2020(did).publicKeyMultibase },
      { ...key2018(did), publicKeyHex: 'abcd' },
    ]) {
      expectThrows(
        () => assertEd25519VerificationMethod(asVm(vm)),
        ErrorCodes.DID_DOC_INVALID,
        'cheqd_key_invalid',
      );
    }
  });

  it('長大な base58 は二次時間のデコード前に拒否する', () => {
    let calls = 0;
    const decode = spyOn(base58, 'decode').mockImplementation(() => {
      calls++;
      throw new Error('decoder must not run');
    });
    try {
      expectThrows(
        () =>
          assertEd25519VerificationMethod(
            asVm({ ...key2018(did), publicKeyBase58: 'Z'.repeat(100_000) }),
          ),
        ErrorCodes.DID_DOC_INVALID,
        'cheqd_key_invalid',
      );
      expect(calls).toBe(0);
    } finally {
      decode.mockRestore();
    }
  });

  it('Ed25519 の 3 表現（2018 / 2020 / JsonWebKey2020）と実機の鍵を受理する', () => {
    assertEd25519VerificationMethod(asVm(key2018(did)));
    assertEd25519VerificationMethod(asVm(key2020(did)));
    assertEd25519VerificationMethod(asVm(keyJwk(did)));
    assertEd25519VerificationMethod(
      asVm({
        id: `${did}#key1`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: LIVE_KEY_MULTIBASE,
      }),
    );
  });

  it('secp256k1 / P-256 の JsonWebKey2020・Ed25519 以外の type は 2010 cheqd_key_unsupported', () => {
    for (const vm of [
      { id: `${did}#a`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: secp256k1Jwk() },
      { id: `${did}#b`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: p256Jwk() },
      {
        id: `${did}#c`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: did,
        publicKeyBase58: 'x',
      },
      { id: `${did}#d`, type: 'X25519KeyAgreementKey2019', controller: did, publicKeyBase58: 'x' },
    ]) {
      expectThrows(
        () => assertEd25519VerificationMethod(asVm(vm)),
        ErrorCodes.DID_DOC_INVALID,
        'cheqd_key_unsupported',
      );
    }
    // Ed25519 の JWK 表現でも kty / crv が違えば未対応（x25519 など）。
    expectThrows(
      () =>
        assertEd25519VerificationMethod(
          asVm({
            id: `${did}#e`,
            type: 'JsonWebKey2020',
            controller: did,
            publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: ed25519Jwk().x },
          }),
        ),
      ErrorCodes.DID_DOC_INVALID,
      'cheqd_key_unsupported',
    );
  });

  it('対象の type で鍵が読めない（欠落・長さ・multicodec・文字種）は 2010 cheqd_key_invalid', () => {
    const wrongCodec = key2020(did);
    wrongCodec.publicKeyMultibase = `z${'1'.repeat(10)}`;
    for (const vm of [
      { id: `${did}#a`, type: 'Ed25519VerificationKey2018', controller: did },
      {
        id: `${did}#b`,
        type: 'Ed25519VerificationKey2018',
        controller: did,
        publicKeyBase58: 'abc',
      },
      {
        id: `${did}#c`,
        type: 'Ed25519VerificationKey2018',
        controller: did,
        publicKeyBase58: '0OIl',
      },
      {
        id: `${did}#d`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: 'z6Mk',
      },
      wrongCodec,
      // 2018 の base58 を 2020 の multibase として渡した（multicodec なし）。
      {
        id: `${did}#e`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: `z${String(key2018(did).publicKeyBase58)}`,
      },
      { id: `${did}#f`, type: 'JsonWebKey2020', controller: did },
      {
        id: `${did}#g`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' },
      },
    ]) {
      expectThrows(
        () => assertEd25519VerificationMethod(asVm(vm)),
        ErrorCodes.DID_DOC_INVALID,
        'cheqd_key_invalid',
      );
    }
  });
});
