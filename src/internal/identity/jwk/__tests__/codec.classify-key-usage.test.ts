/**
 * `classifyKeyUsage` の JWK メンバ読み取りが own 限定であることの回帰テスト。
 *
 * `resolveDidJwk` 経由の JWK は `decodeDidJwk`（`parseJsonWithoutPrototype`）由来で `null`
 * プロトタイプのため影響を受けないが、公開 API の `createDidJwk(jwk)` は**呼び出し側が組んだ
 * plain object** をそのまま受け取るため `Object.prototype` を継承する。鎖読みだと、
 *
 * - `kty` / `crv` / `x` / `y` を欠く JWK が汚染値で補われて**受理**される（fail-open）、
 * - `use` を指定していない鍵の用途が汚染値で**書き換え**られる（署名鍵が鍵交換専用に化ける）、
 * - `d` の不在チェックが `Object.prototype.d` を拾って正当な公開鍵 JWK を**誤って拒否**する（DoS）、
 *
 * という非対称な壊れ方をする。`classifyKeyUsage` は `codec.ts` から export されているため直接も
 * 検証するが、実際に脆弱な経路は `createDidJwk` なのでそちらを主軸に据える。
 */

import { describe, expect, test } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../did.js';
import { classifyKeyUsage } from '../codec.js';
import { createDidJwk } from '../method-jwk.js';

/** 既知の公開鍵 JWK サンプル（W3C did:jwk 仕様の例ベース）。 */
const P256_JWK: PublicKeyJwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0',
  y: '_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE',
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

/** EC 形状の汚染値一式（`kty` / `crv` / `x` / `y`）。 */
const EC_POLLUTION: Readonly<Record<string, unknown>> = {
  kty: 'EC',
  crv: 'P-256',
  x: P256_JWK.x,
  y: P256_JWK.y,
};

/** `fn` が `2001`（INVALID_DID）の VericertsError を投げることを表明する。 */
function expectInvalidDid(fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    return;
  }
  throw new Error('should have thrown');
}

describe('createDidJwk: 欠落メンバが Object.prototype 汚染で補われない', () => {
  test.each([
    ['全メンバ欠落', {}],
    ['kty のみ自前', { kty: 'EC' }],
    ['kty / crv のみ自前', { kty: 'EC', crv: 'P-256' }],
    ['y 欠落', { kty: 'EC', crv: 'P-256', x: P256_JWK.x }],
  ])('EC 形状の汚染下で %s の JWK は 2001 で拒否する', (_label, jwk) => {
    withPollutedPrototype(EC_POLLUTION, () => {
      expectInvalidDid(() => createDidJwk(jwk));
    });
  });

  test.each([
    ['全メンバ欠落', {}],
    ['kty のみ自前', { kty: 'OKP' }],
    ['x 欠落', { kty: 'OKP', crv: 'Ed25519' }],
  ])('OKP(Ed25519) 形状の汚染下で %s の JWK は 2001 で拒否する', (_label, jwk) => {
    withPollutedPrototype({ kty: 'OKP', crv: 'Ed25519', x: ED25519_JWK.x }, () => {
      expectInvalidDid(() => createDidJwk(jwk));
    });
  });

  test('OKP(X25519) 形状の汚染下で x を欠く JWK は 2001 で拒否する', () => {
    withPollutedPrototype({ kty: 'OKP', crv: 'X25519', x: X25519_JWK.x }, () => {
      expectInvalidDid(() => createDidJwk({ kty: 'OKP', crv: 'X25519' }));
      expectInvalidDid(() => createDidJwk({}));
    });
  });

  test('アクセサ形式の汚染でも欠落メンバは補われない', () => {
    // データ汚染だけを弾く実装（汚染値との同一性比較など）を素通りさせないための非対称ガード。
    withPollutedPrototypeAccessor(
      {
        kty: () => 'EC',
        crv: () => 'P-256',
        x: () => P256_JWK.x,
        y: () => P256_JWK.y,
      },
      () => {
        expectInvalidDid(() => createDidJwk({}));
      },
    );
  });
});

describe('createDidJwk: use は自身のプロパティとしてのみ効く', () => {
  test('use を指定していない EC 鍵は Object.prototype.use=enc で署名用途を奪われない', () => {
    withPollutedPrototype({ use: 'enc' }, () => {
      const doc = createDidJwk(P256_JWK);
      const ref = `${doc.id}#0`;
      expect(doc.authentication).toEqual([ref]);
      expect(doc.assertionMethod).toEqual([ref]);
      expect(doc.keyAgreement).toEqual([ref]);
    });
  });

  test('use を指定していない Ed25519 鍵は Object.prototype.use=enc で拒否されない', () => {
    // 鎖読みだと「Ed25519 × use=enc は矛盾」の検査が汚染値を拾って正当な鍵を落とす（DoS）。
    withPollutedPrototype({ use: 'enc' }, () => {
      const doc = createDidJwk(ED25519_JWK);
      expect(doc.authentication).toEqual([`${doc.id}#0`]);
      expect(doc.keyAgreement).toBeUndefined();
    });
  });

  test('use を指定していない X25519 鍵は Object.prototype.use=sig で拒否されない', () => {
    withPollutedPrototype({ use: 'sig' }, () => {
      const doc = createDidJwk(X25519_JWK);
      expect(doc.keyAgreement).toEqual([`${doc.id}#0`]);
      expect(doc.authentication).toEqual([]);
    });
  });

  test('不正な use を自身に持つ JWK は汚染の有無に関わらず 2001 で拒否する', () => {
    expectInvalidDid(() => createDidJwk({ ...P256_JWK, use: 'wrap' }));
    withPollutedPrototype({ use: 'sig' }, () => {
      expectInvalidDid(() => createDidJwk({ ...P256_JWK, use: 'wrap' }));
    });
  });
});

describe('createDidJwk: d 不在チェックは own 限定', () => {
  test.each([
    ['EC P-256', P256_JWK],
    ['OKP Ed25519', ED25519_JWK],
    ['OKP X25519', X25519_JWK],
  ])('d を持たない正当な %s は Object.prototype.d 汚染下でも受理する', (_label, jwk) => {
    withPollutedPrototype({ d: 'ATTACKER_SECRET' }, () => {
      const doc = createDidJwk(jwk);
      expect(doc.verificationMethod[0]?.publicKeyJwk).toEqual(jwk);
    });
  });

  test('d を自身に持つ JWK は汚染の有無に関わらず 2001 で拒否する', () => {
    // own 限定化で秘密鍵混入の検知が緩まないことの回帰ガード。
    const withSecret = { ...P256_JWK, d: 'ZZZ' };
    expectInvalidDid(() => createDidJwk(withSecret));
    withPollutedPrototype({ d: 'ATTACKER_SECRET' }, () => {
      expectInvalidDid(() => createDidJwk(withSecret));
    });
  });
});

describe('createDidJwk: 自身のメンバは汚染下でも優先される（陽性対照）', () => {
  test('矛盾する汚染下でも EC P-256 の自身の値で分類される', () => {
    withPollutedPrototype({ kty: 'OKP', crv: 'X25519', use: 'enc', x: 'zzz', y: 'zzz' }, () => {
      const doc = createDidJwk(P256_JWK);
      const ref = `${doc.id}#0`;
      expect(doc.authentication).toEqual([ref]);
      expect(doc.keyAgreement).toEqual([ref]);
      expect(doc.verificationMethod[0]?.publicKeyJwk).toEqual(P256_JWK);
    });
  });

  test('矛盾する汚染下でも Ed25519 の自身の値で署名専用に分類される', () => {
    withPollutedPrototype({ kty: 'EC', crv: 'P-256', use: 'enc', y: P256_JWK.y }, () => {
      const doc = createDidJwk(ED25519_JWK);
      expect(doc.authentication).toEqual([`${doc.id}#0`]);
      expect(doc.keyAgreement).toBeUndefined();
    });
  });

  test('矛盾する汚染下でも自身の use=sig が EC の keyAgreement を落とす', () => {
    withPollutedPrototype({ use: 'enc' }, () => {
      const doc = createDidJwk({ ...P256_JWK, use: 'sig' });
      expect(doc.authentication).toEqual([`${doc.id}#0`]);
      expect(doc.keyAgreement).toBeUndefined();
    });
  });
});

describe('classifyKeyUsage 単体', () => {
  test('EC 形状の汚染下でメンバを欠く JWK は 2001 で拒否する', () => {
    withPollutedPrototype(EC_POLLUTION, () => {
      expectInvalidDid(() => classifyKeyUsage({}));
    });
  });

  test('Object.prototype.d 汚染下でも d を持たない JWK は分類できる', () => {
    withPollutedPrototype({ d: 'ATTACKER_SECRET' }, () => {
      expect(classifyKeyUsage(P256_JWK)).toEqual({ signing: true, keyAgreement: true });
    });
  });

  test('汚染下でも自身の kty / crv / use による分類は変わらない', () => {
    withPollutedPrototype({ kty: 'EC', crv: 'P-256', use: 'enc' }, () => {
      expect(classifyKeyUsage(X25519_JWK)).toEqual({ signing: false, keyAgreement: true });
      expect(classifyKeyUsage(ED25519_JWK)).toEqual({ signing: true, keyAgreement: false });
    });
  });
});
