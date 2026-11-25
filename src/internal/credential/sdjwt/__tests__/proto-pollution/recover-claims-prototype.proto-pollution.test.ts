/**
 * `recoverClaims` の戻り値（公開 API `VerifiedSdJwt.claims`）が `Object.prototype` を
 * 継承しないことの回帰テスト。
 *
 * `recoverClaims` は `payload` を own 限定で読み、クレーム設定も `Object.defineProperty`
 * で行う。しかし**戻り値そのもの**が `{}` リテラルだったため、`Object.prototype` を
 * 継承したまま呼び出し側へ届いていた。`claims` は任意のクレーム名で読まれる面
 * （`verified.claims.isAdmin` / `verified.claims.exp` 等）なので、`Object.prototype.isAdmin` の
 * 汚染下では**そのクレームを持たない VC でも継承値が「検証済みクレーム」として読める**。
 *
 * `payload` はパース境界（`parse-json.ts` の `parseJsonWithoutPrototype`）で `null`
 * プロトタイプになって届く。公開するクレームにも同じ性質を保つため、`Object.create(null)` に写す。
 *
 * **トートロジー回避**: プロトタイプの同一性だけでなく、(1) 汚染値が `claims.<name>` 経由で
 * 読めないこと、(2) 実在するクレームは従来どおり読めること（対照）、(3) 汚染名と実在名を
 * **食い違わせた**状態で own 側の値だけが返ること、の 3 点を検証する。
 *
 * 親ディレクトリ `sdjwt/__tests__/` は Linterly のディレクトリ行数上限（2000 行）を既に超過している
 * ため、本ファイルはサブディレクトリに置く。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { createSdJwt } from '../../sdjwt.js';
import { verifySdJwt } from '../../verify.js';

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const VCT = 'https://example.com/credentials/identity';
const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);

const baseOpts = { issuerKey: ISSUER_JWK, nowSeconds: NOW } as const;

/** `isAdmin` を持たない、平文クレームだけの正当な SD-JWT。 */
function issuePlain(claims: Readonly<Record<string, unknown>>): string {
  return createSdJwt(ISSUER_SIGNER, { vct: VCT, claims, disclosureClaims: [], nowSeconds: NOW });
}

describe('VerifiedSdJwt.claims が Object.prototype を継承しない', () => {
  it('戻り値のプロトタイプは null である', () => {
    const verified = verifySdJwt(issuePlain({ name: 'Alice' }), baseOpts);

    expect(Object.getPrototypeOf(verified.claims)).toBe(null);
  });

  it('Object.prototype.isAdmin の汚染は claims 経由で読めない', () => {
    const sdJwt = issuePlain({ name: 'Alice' });

    const isAdmin = withPollutedPrototype({ isAdmin: true }, () => {
      const verified = verifySdJwt(sdJwt, baseOpts);
      // 利用側の典型的な読み方（プロパティの直接読み）。`{}` リテラルを返していた頃は
      // ここで汚染値 `true` が「検証済みクレーム」として読めていた。
      return (verified.claims as Record<string, unknown>).isAdmin;
    });

    expect(isAdmin).toBeUndefined();
  });

  it('汚染名と実在名が食い違っても own のクレームだけが返る', () => {
    // 実在するのは `role: 'user'`。汚染側は同名 `role: 'admin'` と、VC に無い `isAdmin: true`。
    const sdJwt = issuePlain({ role: 'user' });

    const read = withPollutedPrototype({ role: 'admin', isAdmin: true }, () => {
      const claims = verifySdJwt(sdJwt, baseOpts).claims as Record<string, unknown>;
      return { role: claims.role, isAdmin: claims.isAdmin };
    });

    expect(read.role).toBe('user');
    expect(read.isAdmin).toBeUndefined();
  });

  it('対照: 実在するクレームは従来どおり読める（Object.keys / スプレッドも維持）', () => {
    const verified = verifySdJwt(issuePlain({ name: 'Alice', age: 30 }), baseOpts);
    const claims = verified.claims as Record<string, unknown>;

    expect(claims.name).toBe('Alice');
    expect(claims.age).toBe(30);
    expect(Object.hasOwn(claims, 'name')).toBe(true);
    expect(Object.keys(claims)).toContain('name');
    expect({ ...claims }.age).toBe(30);
    expect(JSON.parse(JSON.stringify(claims)).name).toBe('Alice');
  });

  it('選択的開示から復元したクレームも同じ戻り値に載る（対照）', () => {
    const sdJwt = createSdJwt(ISSUER_SIGNER, {
      vct: VCT,
      claims: { name: 'Alice', secret: 'hidden' },
      disclosureClaims: ['secret'],
      salts: { secret: 'salt-secret' },
      nowSeconds: NOW,
    });

    const verified = verifySdJwt(sdJwt, baseOpts);

    expect(Object.getPrototypeOf(verified.claims)).toBe(null);
    expect((verified.claims as Record<string, unknown>).secret).toBe('hidden');
  });
});
