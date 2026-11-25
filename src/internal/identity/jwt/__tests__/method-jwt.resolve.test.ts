/**
 * did:jwt 解決（resolveDidJwt / MethodJwt）の正常系・鍵バインドテスト。
 *
 * 実鍵で JWT を署名してテストフィクスチャを構築する（モック禁止）。
 * - ES256（P-256）と ES256K（secp256k1）の正常解決
 * - 署名改竄・別鍵・alg/crv 不一致の拒否
 *
 * 異常系（プレフィックス / 構造 / 時刻クレーム / ライフサイクル非対応）は
 * `method-jwt.errors.test.ts` を参照（300 行上限のため分割）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { MethodJwt, resolveDidJwt } from '../method-jwt.js';
import {
  buildDidJwt,
  NOW,
  p256Fixture,
  secp256k1Fixture,
  uncompressedToXY,
} from './jwt-fixtures.js';

const p256 = p256Fixture(new Uint8Array(32).fill(7));
const secp = secp256k1Fixture(new Uint8Array(32).fill(9));

describe('resolveDidJwt 正常系', () => {
  it('ES256（P-256）の did:jwt を解決し DID Document を返す', () => {
    const did = buildDidJwt(p256);
    const doc = resolveDidJwt(did, NOW);
    expect(doc.id).toBe(did);
    expect(doc['@context']).toEqual(['https://www.w3.org/ns/did/v1']);
    expect(doc.verificationMethod).toHaveLength(1);
    const vm = doc.verificationMethod[0];
    expect(vm?.id).toBe('#key-1');
    expect(vm?.type).toBe('JsonWebKey');
    expect(vm?.controller).toBe(did);
    expect(vm?.publicKeyJwk).toEqual(p256.jwk);
    expect(doc.authentication).toEqual(['#key-1']);
    expect(doc.assertionMethod).toEqual(['#key-1']);
  });

  it('ES256K（secp256k1）の did:jwt を解決する', () => {
    const did = buildDidJwt(secp);
    const doc = resolveDidJwt(did, NOW);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod[0]?.publicKeyJwk).toEqual(secp.jwk);
  });

  it('nbf <= now < exp の範囲内なら解決する', () => {
    const did = buildDidJwt(p256, {
      payloadOverrides: { nbf: NOW - 10, exp: NOW + 10 },
    });
    expect(resolveDidJwt(did, NOW).id).toBe(did);
  });

  it('authentication / assertionMethod 省略時は VM id にフォールバックする', () => {
    const did = buildDidJwt(p256, {
      payloadOverrides: { authentication: undefined, assertionMethod: undefined },
    });
    const doc = resolveDidJwt(did, NOW);
    expect(doc.authentication).toEqual(['#key-1']);
    expect(doc.assertionMethod).toEqual(['#key-1']);
  });

  it('MethodJwt.resolve は method() が jwt で解決できる', async () => {
    const method = new MethodJwt();
    expect(method.method()).toBe('jwt');
    // exp/nbf を未指定にし、Date.now() 基準でも解決可能なケースで確認する。
    const did = buildDidJwt(p256);
    const doc = await method.resolve(did);
    expect(doc.id).toBe(did);
  });
});

describe('resolveDidJwt 鍵バインド・署名検証', () => {
  it('署名が改竄されていると INVALID_DID で拒否する', () => {
    const did = buildDidJwt(p256, { tamperSignature: true });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
    try {
      resolveDidJwt(did, NOW);
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('別鍵の公開鍵 JWK が埋め込まれていると署名検証に失敗する', () => {
    // 署名は p256 の秘密鍵だが、JWK は別の公開鍵に差し替える。
    const otherPub = getP256PublicKey(new Uint8Array(32).fill(11), false);
    const { x, y } = uncompressedToXY(otherPub);
    const did = buildDidJwt(p256, {
      payloadOverrides: {
        verificationMethod: [
          { id: '#key-1', type: 'JsonWebKey', publicKeyJwk: { kty: 'EC', crv: 'P-256', x, y } },
        ],
      },
    });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });

  it('alg と JWK crv が不一致（ES256 だが crv=secp256k1）だと拒否する', () => {
    const otherPub = getSecp256k1PublicKey(new Uint8Array(32).fill(9), false);
    const { x, y } = uncompressedToXY(otherPub);
    const did = buildDidJwt(p256, {
      payloadOverrides: {
        verificationMethod: [
          {
            id: '#key-1',
            type: 'JsonWebKey',
            publicKeyJwk: { kty: 'EC', crv: 'secp256k1', x, y },
          },
        ],
      },
    });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });
});
