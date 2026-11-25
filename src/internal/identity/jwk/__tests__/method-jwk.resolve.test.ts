/**
 * resolveDidJwk / MethodJwk の解決・エラー検証。
 *
 * 既知の did:jwk 文字列を解決して DID Document が構築されること、
 * 形式不正・未対応 JWK が VericertsError(2001) になること、
 * update / deactivate が METHOD_NOT_SUPPORTED(2002) になることを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../did.js';
import { MethodJwk, resolveDidJwk } from '../method-jwk.js';

/** JWK を did:jwk 文字列に符号化するヘルパ（テスト用）。 */
function toDidJwk(jwk: Record<string, unknown>): string {
  const encoded = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(jwk)));
  return `did:jwk:${encoded}`;
}

const P256_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0',
  y: '_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE',
};

describe('resolveDidJwk', () => {
  it('既知の did:jwk を解決して publicKeyJwk を復元する', () => {
    const did = toDidJwk(P256_JWK as Record<string, unknown>);
    const doc = resolveDidJwk(did);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod[0]?.publicKeyJwk).toEqual(P256_JWK);
    expect(doc.verificationMethod[0]?.type).toBe('JsonWebKey2020');
  });

  it('プレフィックスが did:jwk: でない場合は INVALID_DID', () => {
    expect(() => resolveDidJwk('did:key:zABC')).toThrow(VericertsError);
    try {
      resolveDidJwk('did:key:zABC');
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('identifier が空の場合は INVALID_DID', () => {
    expect(() => resolveDidJwk('did:jwk:')).toThrow(VericertsError);
  });

  it('base64url として不正な文字列は INVALID_DID', () => {
    // '!' は base64url アルファベット外。
    expect(() => resolveDidJwk('did:jwk:!!!!')).toThrow(VericertsError);
  });

  it('JSON として不正なペイロードは INVALID_DID', () => {
    const encoded = base64urlnopad.encode(new TextEncoder().encode('{not json'));
    expect(() => resolveDidJwk(`did:jwk:${encoded}`)).toThrow(VericertsError);
  });

  it('JSON だが配列の場合は INVALID_DID', () => {
    const did = toDidJwk([] as unknown as Record<string, unknown>);
    expect(() => resolveDidJwk(did)).toThrow(VericertsError);
  });

  it('未対応 kty（RSA）は INVALID_DID', () => {
    const did = toDidJwk({ kty: 'RSA', n: 'AQAB', e: 'AQAB' });
    expect(() => resolveDidJwk(did)).toThrow(VericertsError);
  });

  it('未対応 crv（EC secp256k1）は INVALID_DID', () => {
    const did = toDidJwk({ kty: 'EC', crv: 'secp256k1', x: 'AA', y: 'BB' });
    expect(() => resolveDidJwk(did)).toThrow(VericertsError);
  });

  it('EC で y が欠落している場合は INVALID_DID', () => {
    const did = toDidJwk({ kty: 'EC', crv: 'P-256', x: 'AA' });
    expect(() => resolveDidJwk(did)).toThrow(VericertsError);
  });

  it('秘密鍵パラメータ d を含む JWK は INVALID_DID', () => {
    const did = toDidJwk({ ...(P256_JWK as Record<string, unknown>), d: 'SECRET' });
    expect(() => resolveDidJwk(did)).toThrow(VericertsError);
  });

  it('Ed25519 で use=enc は矛盾のため INVALID_DID', () => {
    const did = toDidJwk({ kty: 'OKP', crv: 'Ed25519', x: 'AA', use: 'enc' });
    expect(() => resolveDidJwk(did)).toThrow(VericertsError);
  });

  it('X25519 で use=sig は矛盾のため INVALID_DID', () => {
    const did = toDidJwk({ kty: 'OKP', crv: 'X25519', x: 'AA', use: 'sig' });
    expect(() => resolveDidJwk(did)).toThrow(VericertsError);
  });

  it('未対応 use 値は INVALID_DID', () => {
    const did = toDidJwk({ ...(P256_JWK as Record<string, unknown>), use: 'other' });
    expect(() => resolveDidJwk(did)).toThrow(VericertsError);
  });
});

describe('MethodJwk', () => {
  it('method() は jwk を返す', () => {
    expect(new MethodJwk().method()).toBe('jwk');
  });

  it('create() は jwk オプションから DID Document を生成する', async () => {
    const method = new MethodJwk();
    const doc = await method.create({
      keyType: 'P-256',
      publicKey: new Uint8Array(0),
      // did:jwk は JWK を直接受け取る（CreateOptions 拡張）。
      jwk: P256_JWK,
    } as never);
    expect(doc.id.startsWith('did:jwk:')).toBe(true);
    expect(doc.verificationMethod[0]?.publicKeyJwk).toEqual(P256_JWK);
  });

  it('create() で jwk 未指定は INVALID_DID', async () => {
    const method = new MethodJwk();
    await expect(method.create({ keyType: 'P-256', publicKey: new Uint8Array(0) })).rejects.toThrow(
      VericertsError,
    );
  });

  it('resolve() は did:jwk を解決する', async () => {
    const did = toDidJwk(P256_JWK as Record<string, unknown>);
    const doc = await new MethodJwk().resolve(did);
    expect(doc.id).toBe(did);
  });

  it('update() は METHOD_NOT_SUPPORTED', async () => {
    const method = new MethodJwk();
    try {
      await method.update('did:jwk:abc', {});
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.METHOD_NOT_SUPPORTED);
    }
  });

  it('deactivate() は METHOD_NOT_SUPPORTED', async () => {
    const method = new MethodJwk();
    try {
      await method.deactivate('did:jwk:abc');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.METHOD_NOT_SUPPORTED);
    }
  });
});
