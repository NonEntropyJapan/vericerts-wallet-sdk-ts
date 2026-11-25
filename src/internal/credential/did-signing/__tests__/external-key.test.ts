/**
 * 取り込んだ秘密鍵 JWK（RFC 7517）からの署名鍵（`createExternalKeySigner`）。
 *
 * P-256 / secp256k1 / Ed25519 の署名が各 alg の検証で通ること、不正な JWK を `1003` / `1030` で拒否することを確かめる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { verifyWithJwk } from '../../vc/jws.js';
import { createExternalKeySigner } from '../external-key.js';
import { externalKey } from './fixtures.js';

const INPUT = new TextEncoder().encode('header.payload');

describe('createExternalKeySigner', () => {
  it.each([
    ['P-256', 'ES256'],
    ['secp256k1', 'ES256K'],
    ['Ed25519', 'EdDSA'],
  ] as const)('%s の秘密鍵 JWK は %s の署名鍵になり、署名が検証できる', (kind, alg) => {
    const key = externalKey(kind, 51);
    const signer = createExternalKeySigner(key.privateKeyJwk, 'did:example:1#k');
    expect(signer.alg).toBe(alg);
    expect(signer.kid).toBe('did:example:1#k');
    expect(signer.publicKeyJwk).toEqual(key.publicKeyJwk);
    expect(Object.keys(signer)).not.toContain('d');
    const signature = signer.sign(INPUT);
    expect(signature).toHaveLength(64);
    expect(verifyWithJwk(alg, { signingInput: INPUT, signature }, key.publicKeyJwk)).toBe(true);
  });

  it('kid を渡さなければ署名鍵に kid を付けない', () => {
    expect('kid' in createExternalKeySigner(externalKey('P-256', 52).privateKeyJwk)).toBe(false);
  });

  it('JWK の x / y が d と一致しなければ 1003（取り違え・改ざんの検出）', () => {
    const a = externalKey('P-256', 53);
    const b = externalKey('P-256', 54);
    expect(() => createExternalKeySigner({ ...a.privateKeyJwk, x: b.publicKeyJwk.x })).toThrow(
      expect.objectContaining({ code: ErrorCodes.INVALID_PRIVATE_KEY }),
    );
  });

  it('d が無い・32 バイトでない・範囲外のスカラーは 1003', () => {
    const key = externalKey('secp256k1', 55);
    const { d: _d, ...publicOnly } = key.privateKeyJwk;
    for (const jwk of [
      publicOnly,
      { ...key.privateKeyJwk, d: 'AAAA' },
      { ...key.privateKeyJwk, d: '!!' },
    ]) {
      expect(() => createExternalKeySigner(jwk)).toThrow(
        expect.objectContaining({ code: ErrorCodes.INVALID_PRIVATE_KEY }),
      );
    }
    const zero = Buffer.alloc(32).toString('base64url');
    expect(() => createExternalKeySigner({ ...key.privateKeyJwk, d: zero })).toThrow(
      expect.objectContaining({ code: ErrorCodes.INVALID_PRIVATE_KEY }),
    );
  });

  it('未対応の鍵種（RSA / P-384 / X25519）は 1030', () => {
    for (const jwk of [
      { kty: 'RSA', n: 'AQAB', e: 'AQAB', d: 'AQAB' },
      { kty: 'EC', crv: 'P-384', d: 'AQAB' },
      { kty: 'OKP', crv: 'X25519', d: 'AQAB' },
    ]) {
      expect(() => createExternalKeySigner(jwk)).toThrow(
        expect.objectContaining({ code: ErrorCodes.UNSUPPORTED_ALGORITHM }),
      );
    }
  });
});
