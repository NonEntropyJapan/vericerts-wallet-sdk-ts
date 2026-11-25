/**
 * クレーム名 `__proto__` による復元結果のプロトタイプ差し替えの回帰テスト。
 *
 * SD-JWT VC のクレーム名は JSON 由来なので `__proto__` を取り得る。素朴な `claims[name] = value`
 * は `name === '__proto__'` のとき **own プロパティを作らず、そのオブジェクトのプロトタイプを
 * 差し替える**。その結果:
 *
 * - 発行時: 当該クレームが署名済み payload から無言で消える。
 * - 検証時: 返した `claims` のプロトタイプが**攻撃者の選んだオブジェクト**になり、利用側が
 *   `claims.exp` / `claims.isAdmin` のように読むと Issuer が署名していない値が**継承値として**
 *   返る（`Object.hasOwn` は false のまま）。本 SDK が塞いでいるプロトタイプ鎖 fail-open を、
 *   検証結果の出力側で作り込むことになる。
 *
 * `Object.defineProperty` による設定でこの 2 つを塞ぐ。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { createSdJwt } from '../../sdjwt.js';
import { verifySdJwt } from '../../verify.js';

const ISSUER_KEY = new Uint8Array(32).fill(7);

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const VCT = 'https://example.com/credentials/identity';
const NOW = 1_767_225_600;

/** `JSON.parse` は `__proto__` を **own プロパティ**として作る（リテラルと違う点）。 */
function claimsWithProtoKey(payloadJson: string): Record<string, unknown> {
  return JSON.parse(payloadJson) as Record<string, unknown>;
}

describe('クレーム名 __proto__ の扱い', () => {
  it('__proto__ の Disclosure が復元結果のプロトタイプを差し替えない', () => {
    const claims = claimsWithProtoKey(
      '{"__proto__":{"isAdmin":true,"exp":9999999999},"name":"Bob"}',
    );
    expect(Object.hasOwn(claims, '__proto__')).toBe(true);

    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['__proto__'],
      claims,
      nowSeconds: NOW,
    });
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });

    // プロトタイプが攻撃者のオブジェクトへ差し替わっていないこと。 `recoverClaims`
    // の戻り値を `Object.create(null)` 由来にしたため、期待値は `Object.prototype` ではなく
    // `null` である（`__proto__` クレームが own プロパティになる不変条件は変わらない）。
    expect(Object.getPrototypeOf(result.claims)).toBe(null);
    // Issuer が署名していない値が継承値として読めないこと。
    expect((result.claims as Record<string, unknown>).isAdmin).toBeUndefined();
    expect((result.claims as Record<string, unknown>).exp).toBeUndefined();
    // クレーム自体は own プロパティとして復元されること（無言で消さない）。
    expect(Object.hasOwn(result.claims, '__proto__')).toBe(true);
    expect(result.claims.name).toBe('Bob');
  });

  it('__proto__ の平文クレームが署名済み payload から消えない', () => {
    const claims = claimsWithProtoKey('{"__proto__":{"polluted":"yes"},"name":"Alice"}');
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: [],
      claims,
      nowSeconds: NOW,
    });
    const segment = sdJwt.split('~')[0]?.split('.')[1] ?? '';
    const payload = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    // 素朴な代入だと `__proto__` は payload から消える。
    expect(Object.keys(payload)).toContain('__proto__');
    expect(payload.name).toBe('Alice');
  });

  it('同名 __proto__ の重複クレームは従来どおり 3010 で拒否される', () => {
    // 平文と Disclosure の両方に `__proto__` があると隠蔽になるため拒否される。
    // （素朴な代入だと `Object.hasOwn` が false のままで重複検知をすり抜けていた。）
    const claims = claimsWithProtoKey('{"__proto__":{"a":1},"name":"Bob"}');
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['__proto__'],
      claims,
      nowSeconds: NOW,
    });
    // Disclosure 部を複製して同名クレームの二重提示を作る。
    const parts = sdJwt.split('~').filter((p) => p.length > 0);
    const duplicated = `${parts.join('~')}~${parts[parts.length - 1]}~`;
    expect(() => verifySdJwt(duplicated, { issuerKey: ISSUER_JWK, nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('通常のクレーム名は従来どおり復元される（正常系）', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      disclosureClaims: ['name'],
      claims: { name: 'Alice', age: 30 },
      salts: { name: 'salt-name' },
      nowSeconds: NOW,
    });
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.age).toBe(30);
    // 正常系でも戻り値は `null` プロトタイプ。
    expect(Object.getPrototypeOf(result.claims)).toBe(null);
  });
});
