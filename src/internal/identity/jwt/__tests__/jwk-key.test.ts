/**
 * EC JWK ヘルパのユニットテスト（`jwkToUncompressedPublicKey` / `jwkToVerificationKey`）。
 *
 *  `eudi/pseudonym/jwk.ts` の同名関数を本モジュールへ統合したため、旧
 * `eudi/pseudonym/__tests__/jwk.test.ts` の観点をここへ引き継いでいる。
 *
 * 検証観点:
 * - 正常な P-256 JWK から 65 バイト非圧縮公開鍵（`0x04 || x || y`）を復元する。
 * - x / y 欠落・型不正・長さ不正・base64url でないは、いずれも呼び出し側が渡した
 *   `errorCode` で拒否する（strict / lenient の双方）。
 * - `expectedCrv` 指定時（strict）は `kty` / `crv` 不一致を拒否する。
 * - `expectedCrv: null`（lenient）は `kty` / `crv` を一切見ない＝誤った / 欠落した `kty` / `crv`
 *   でも座標が正しければ受理する（統合による意図しない厳格化に対する回帰ガード）。
 * - JWK メンバを**自身のプロパティ**としてのみ読む。`Object.prototype` 汚染下で、
 *   メンバを欠く JWK が継承値で補われて受理されないこと・`y` を持たない正当な OKP JWK が
 *   `Object.prototype.y` 汚染で誤って拒否されないこと。
 */

import { describe, expect, test } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import {
  ALG_SPECS,
  jwkToOkpPublicKey,
  jwkToUncompressedPublicKey,
  jwkToVerificationKey,
} from '../jwk-key.js';

/** lenient 呼び出し側が渡すコードの代表（Pseudonym cnf バインド不一致）。 */
const LENIENT_ERR: ErrorCode = ErrorCodes.PSEUDONYM_BINDING_INVALID;
/** strict 呼び出し側（DID / 署名検証 / W2W / JWE）が渡すコード。 */
const STRICT_ERR: ErrorCode = ErrorCodes.INVALID_DID;

/** 有効な P-256 公開鍵 JWK を組み立てる。 */
function validJwk(): { kty: string; crv: string; x: string; y: string } {
  const priv = new Uint8Array(32).fill(7);
  const uncompressed = getP256PublicKey(priv, false);
  return {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlnopad.encode(uncompressed.subarray(1, 33)),
    y: base64urlnopad.encode(uncompressed.subarray(33, 65)),
  };
}

/**
 * 有効な形式の Ed25519 公開鍵 JWK を組み立てる。
 *
 * `jwkToOkpPublicKey` は `x` を 32 バイトへ decode できるかまでしか見ない（曲線上の点かどうかは
 * `verifyEd25519` の責務）ため、テストでは固定の 32 バイト列で足りる。
 */
function validOkpJwk(): { kty: string; crv: string; x: string } {
  return { kty: 'OKP', crv: 'Ed25519', x: base64urlnopad.encode(new Uint8Array(32).fill(9)) };
}

/** `fn` が `code` の VericertsError を投げることを表明する。 */
function expectCode(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
    return;
  }
  throw new Error('should have thrown');
}

describe('jwkToUncompressedPublicKey 座標の検証（strict / lenient 共通）', () => {
  test('有効な JWK から 65 バイト非圧縮公開鍵を復元する', () => {
    const jwk = validJwk();
    const pub = jwkToUncompressedPublicKey(jwk, { expectedCrv: null, errorCode: LENIENT_ERR });
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04);
    expect(base64urlnopad.encode(pub.subarray(1, 33))).toBe(jwk.x);
    expect(base64urlnopad.encode(pub.subarray(33, 65))).toBe(jwk.y);
  });

  test('strict / lenient は同一の非圧縮公開鍵を返す', () => {
    const jwk = validJwk();
    expect(
      jwkToUncompressedPublicKey(jwk, { expectedCrv: 'P-256', errorCode: STRICT_ERR }),
    ).toEqual(jwkToUncompressedPublicKey(jwk, { expectedCrv: null, errorCode: LENIENT_ERR }));
  });

  test.each([
    ['x 欠落', { kty: 'EC', crv: 'P-256', y: validJwk().y }],
    ['y 欠落', { kty: 'EC', crv: 'P-256', x: validJwk().x }],
    ['x が数値', { kty: 'EC', crv: 'P-256', x: 1, y: validJwk().y }],
    ['x が 32 バイトでない', { ...validJwk(), x: base64urlnopad.encode(new Uint8Array(16)) }],
    ['x が base64url でない', { ...validJwk(), x: '!!!not-base64!!!' }],
  ])('%s は呼び出し側の errorCode で拒否する', (_label, jwk) => {
    expectCode(
      () => jwkToUncompressedPublicKey(jwk, { expectedCrv: null, errorCode: LENIENT_ERR }),
      LENIENT_ERR,
    );
    expectCode(
      () => jwkToUncompressedPublicKey(jwk, { expectedCrv: 'P-256', errorCode: STRICT_ERR }),
      STRICT_ERR,
    );
  });

  test.each([
    ['4081（DPoP 署名不正）', ErrorCodes.DPOP_SIGNATURE_INVALID],
    ['4080（DPoP 形式不正）', ErrorCodes.DPOP_PROOF_MALFORMED],
  ])('base64url デコード失敗でも %s がそのまま送出される', (_label, code) => {
    // base64urlDecode（2001 固定）を再利用すると壊れる経路の回帰ガード。
    expectCode(
      () =>
        jwkToUncompressedPublicKey(
          { ...validJwk(), y: '###' },
          { expectedCrv: null, errorCode: code },
        ),
      code,
    );
  });
});

describe('jwkToUncompressedPublicKey expectedCrv 指定時（strict）', () => {
  test.each([
    ['kty が OKP', { ...validJwk(), kty: 'OKP' }],
    ['kty 欠落', { crv: 'P-256', x: validJwk().x, y: validJwk().y }],
    ['crv が secp256k1', { ...validJwk(), crv: 'secp256k1' }],
    ['crv 欠落', { kty: 'EC', x: validJwk().x, y: validJwk().y }],
  ])('%s は errorCode で拒否する', (_label, jwk) => {
    expectCode(
      () => jwkToUncompressedPublicKey(jwk, { expectedCrv: 'P-256', errorCode: STRICT_ERR }),
      STRICT_ERR,
    );
  });
});

describe('jwkToUncompressedPublicKey expectedCrv: null 指定時（lenient）', () => {
  // 統合時に kty/crv 検査を lenient 経路へ持ち込まないことの回帰ガード。
  // DPoP は `toDpopPublicKeyJwk` 側で、Pseudonym は派生鍵の性質で kty/crv を保証している。
  test.each([
    ['kty が OKP', { ...validJwk(), kty: 'OKP' }],
    ['kty / crv 欠落', { x: validJwk().x, y: validJwk().y }],
    ['crv が P-384', { ...validJwk(), crv: 'P-384' }],
  ])('%s でも座標が正しければ受理する', (_label, jwk) => {
    const pub = jwkToUncompressedPublicKey(jwk, { expectedCrv: null, errorCode: LENIENT_ERR });
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04);
  });
});

describe('jwkToVerificationKey', () => {
  test('ES256 の EC JWK を 65 バイト非圧縮公開鍵へ変換する', () => {
    const spec = ALG_SPECS.ES256;
    if (spec === undefined) {
      throw new Error('ES256 spec missing');
    }
    expect(jwkToVerificationKey(validJwk(), spec).length).toBe(65);
  });

  test.each([
    ['crv 不一致', { ...validJwk(), crv: 'secp256k1' }],
    ['x が base64url でない', { ...validJwk(), x: '!!!' }],
  ])('%s は 2001（INVALID_DID）で拒否する', (_label, jwk) => {
    const spec = ALG_SPECS.ES256;
    if (spec === undefined) {
      throw new Error('ES256 spec missing');
    }
    expectCode(() => jwkToVerificationKey(jwk, spec), ErrorCodes.INVALID_DID);
  });
});

describe('Object.prototype 汚染下の JWK メンバ読み取り', () => {
  // パース由来の JWK（did:jwk / did:jwt の `publicKeyJwk`、SD-JWT の `cnf`）は
  // `parseJsonWithoutPrototype` 経由で `null` プロトタイプになるが、`verifyCredential` の
  // `opts.key.publicKeyJwk` や W2W の署名者 JWK のようにパース境界を通らない呼び出し側供給 / DI 由来の
  // JWK は `Object.prototype` を継承する。鎖読みだとメンバを欠く JWK が継承値で補われて受理され、
  // 逆に `y` の不在チェックは `Object.prototype.y` 汚染下で正当な JWK を誤って拒否する。
  test('kty / crv を欠く EC JWK は汚染値で補われず strict で拒否する', () => {
    const { x, y } = validJwk();
    withPollutedPrototype({ kty: 'EC', crv: 'P-256' }, () => {
      expectCode(
        () => jwkToUncompressedPublicKey({ x, y }, { expectedCrv: 'P-256', errorCode: STRICT_ERR }),
        STRICT_ERR,
      );
    });
  });

  test('x / y を欠く EC JWK は汚染値の座標で補われず拒否する', () => {
    const { x, y } = validJwk();
    withPollutedPrototype({ x, y }, () => {
      expectCode(
        () =>
          jwkToUncompressedPublicKey(
            { kty: 'EC', crv: 'P-256' },
            { expectedCrv: 'P-256', errorCode: STRICT_ERR },
          ),
        STRICT_ERR,
      );
      // lenient（`expectedCrv: null`）も座標だけは必ず own で要求する。
      expectCode(
        () => jwkToUncompressedPublicKey({}, { expectedCrv: null, errorCode: LENIENT_ERR }),
        LENIENT_ERR,
      );
    });
  });

  test('kty / crv を欠く OKP JWK は汚染値で補われず拒否する', () => {
    const { x } = validOkpJwk();
    withPollutedPrototype({ kty: 'OKP', crv: 'Ed25519' }, () => {
      expectCode(() => jwkToOkpPublicKey({ x }, 'Ed25519'), ErrorCodes.INVALID_DID);
    });
  });

  test('x を欠く OKP JWK は汚染値の x で補われず拒否する', () => {
    const { kty, crv, x } = validOkpJwk();
    withPollutedPrototype({ x }, () => {
      expectCode(() => jwkToOkpPublicKey({ kty, crv }, 'Ed25519'), ErrorCodes.INVALID_DID);
    });
  });

  test('y を持たない正当な OKP JWK は Object.prototype.y 汚染下でも受理する', () => {
    // 読み取りの非対称の裏側。鎖読みだと `y` 不在チェックが継承値を拾って正当な鍵を拒否する（DoS）。
    const jwk = validOkpJwk();
    withPollutedPrototype({ y: validJwk().y }, () => {
      expect(jwkToOkpPublicKey(jwk, 'Ed25519').length).toBe(32);
    });
  });

  test('自身のメンバを持つ正当な EC JWK は汚染下でも退行しない', () => {
    const jwk = validJwk();
    withPollutedPrototype({ kty: 'OKP', crv: 'P-384', x: 'zzz', y: 'zzz' }, () => {
      const pub = jwkToUncompressedPublicKey(jwk, {
        expectedCrv: 'P-256',
        errorCode: STRICT_ERR,
      });
      expect(pub.length).toBe(65);
      expect(base64urlnopad.encode(pub.subarray(1, 33))).toBe(jwk.x);
    });
  });
});
