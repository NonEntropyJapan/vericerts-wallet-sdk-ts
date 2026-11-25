/**
 * `certSignatureAlgOf` の単体テスト ―― JWS `alg` → 証明書署名アルゴリズムの写像。
 *
 * `alg` の抽出（JOSE Header の own 限定読み）は `jwsAlgOf` の責務で、本関数は受け取った
 * 文字列を許可リストへ引くだけである。`verifyJarSignature` 経由の経路は
 * `jar-signature.trust.test.ts` が担う。
 */

import { describe, expect, it } from 'bun:test';
import { certSignatureAlgOf } from '../jar-x5c.js';

describe('certSignatureAlgOf', () => {
  it('alg が undefined なら undefined を返す', () => {
    expect(certSignatureAlgOf(undefined)).toBeUndefined();
  });

  it('許可リストに無い alg なら undefined を返す', () => {
    expect(certSignatureAlgOf('none')).toBeUndefined();
    expect(certSignatureAlgOf('HS256')).toBeUndefined();
    expect(certSignatureAlgOf('PS256')).toBeUndefined();
  });

  it('許可リストにある alg を証明書署名アルゴリズムへ写す', () => {
    expect(certSignatureAlgOf('RS256')).toBe('RSASSA-PKCS1-v1_5-SHA256');
    expect(certSignatureAlgOf('ES256')).toBe('ECDSA-P256-SHA256');
  });
});
