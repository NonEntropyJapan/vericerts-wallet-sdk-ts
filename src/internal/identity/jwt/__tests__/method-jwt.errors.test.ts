/**
 * did:jwt 解決（resolveDidJwt / MethodJwt）の異常系・時刻クレーム・ライフサイクル非対応テスト。
 *
 * 実鍵で JWT を署名してテストフィクスチャを構築する（モック禁止）。
 * - id 不一致・未対応 alg（RS256 / HS256）・構造不正の拒否
 * - exp / nbf の境界
 * - create / update / deactivate が METHOD_NOT_SUPPORTED
 *
 * 正常系・鍵バインドは `method-jwt.resolve.test.ts` を参照（300 行上限のため分割）。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MethodJwt, resolveDidJwt } from '../method-jwt.js';
import { b64uText, buildDidJwt, NOW, p256Fixture } from './jwt-fixtures.js';

const p256 = p256Fixture(new Uint8Array(32).fill(7));

describe('resolveDidJwt 異常系', () => {
  it('did:jwt: プレフィックスでないと INVALID_DID', () => {
    expect(() => resolveDidJwt('did:key:z6Mk', NOW)).toThrow(VericertsError);
  });

  it('識別子が空だと INVALID_DID', () => {
    expect(() => resolveDidJwt('did:jwt:', NOW)).toThrow(VericertsError);
  });

  it('base64url として不正だと INVALID_DID', () => {
    expect(() => resolveDidJwt('did:jwt:@@@invalid', NOW)).toThrow(VericertsError);
  });

  it('識別子が不正 UTF-8 の base64url だと TypeError ではなく INVALID_DID', () => {
    const did = `did:jwt:${base64urlnopad.encode(new Uint8Array([0xff, 0xfe, 0xfd]))}`;
    expect(() => resolveDidJwt(did, NOW)).toThrow(
      expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
    );
  });

  it('JWT セグメント数が 3 でないと INVALID_DID', () => {
    const did = `did:jwt:${b64uText('a.b')}`;
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });

  it('payload.id が did:jwt: メソッドでないと INVALID_DID', () => {
    const did = buildDidJwt(p256, { payloadOverrides: { id: 'did:key:z6Mk' } });
    try {
      resolveDidJwt(did, NOW);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('payload.id が did:jwt: メソッドなら解決できる（メソッド束縛）', () => {
    const did = buildDidJwt(p256, {
      payloadOverrides: { id: 'did:jwt:abc', iss: 'did:jwt:abc', sub: 'did:jwt:abc' },
    });
    expect(resolveDidJwt(did, NOW).id).toBe(did);
  });

  it('未対応 alg（HS256）は INVALID_DID', () => {
    // ALG_SPECS に無い alg は署名検証不能のため DID 形式不正へ正規化される。
    const did = buildDidJwt(p256, { headerOverrides: { alg: 'HS256' } });
    try {
      resolveDidJwt(did, NOW);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('alg=EdDSA だが publicKeyJwk が EC なら INVALID_DID（alg と鍵種別の不一致）', () => {
    // EdDSA は OKP/Ed25519 鍵でしか検証できない（alg confusion 防止）。
    const did = buildDidJwt(p256, { headerOverrides: { alg: 'EdDSA' } });
    try {
      resolveDidJwt(did, NOW);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('未知 alg（RS256）は INVALID_DID', () => {
    const did = buildDidJwt(p256, { headerOverrides: { alg: 'RS256' } });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });

  // 回帰: ALG_SPECS が通常のオブジェクトリテラルだと `alg: "constructor"` 等が
  // Object.prototype にヒットし、`ALG_SPECS[alg] === undefined` の未対応 alg ガードを
  // すり抜けていた。spec.kty / spec.crv が undefined になるため、crv を省いた EC JWK が
  // jwkToVerificationKey を通過し、spec.verify が関数でないため未捕捉の TypeError が
  // 送出されていた（VericertsError(2001) を返す契約違反）。
  it.each([
    'constructor',
    'toString',
    'valueOf',
    'hasOwnProperty',
  ])('Object.prototype 由来の alg（%s）は TypeError ではなく INVALID_DID', (alg) => {
    // crv を省いた EC JWK。spec.crv === undefined と一致してしまう入力を再現する。
    const { crv: _crv, ...jwkWithoutCrv } = p256.jwk as Record<string, unknown>;
    const did = buildDidJwt(p256, {
      headerOverrides: { alg },
      payloadOverrides: {
        verificationMethod: [{ id: '#key-1', type: 'JsonWebKey', publicKeyJwk: jwkWithoutCrv }],
      },
    });
    try {
      resolveDidJwt(did, NOW);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    }
  });

  it('verificationMethod が空配列だと INVALID_DID', () => {
    const did = buildDidJwt(p256, { payloadOverrides: { verificationMethod: [] } });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });

  it('publicKeyJwk を持たない VM だと INVALID_DID', () => {
    const did = buildDidJwt(p256, {
      payloadOverrides: { verificationMethod: [{ id: '#key-1', type: 'JsonWebKey' }] },
    });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });
});

describe('resolveDidJwt 時刻クレーム', () => {
  it('exp を過ぎていると INVALID_DID', () => {
    const did = buildDidJwt(p256, { payloadOverrides: { exp: NOW - 1 } });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });

  it('now == exp は期限切れ扱い（INVALID_DID）', () => {
    const did = buildDidJwt(p256, { payloadOverrides: { exp: NOW } });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });

  it('nbf より前だと INVALID_DID', () => {
    const did = buildDidJwt(p256, { payloadOverrides: { nbf: NOW + 1 } });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });

  it('now == nbf は有効（解決成功）', () => {
    const did = buildDidJwt(p256, { payloadOverrides: { nbf: NOW } });
    expect(resolveDidJwt(did, NOW).id).toBe(did);
  });

  it('exp が数値でないと INVALID_DID', () => {
    const did = buildDidJwt(p256, { payloadOverrides: { exp: 'soon' } });
    expect(() => resolveDidJwt(did, NOW)).toThrow(VericertsError);
  });

  // nowSeconds が非有限数だと比較が常に false になり期限切れ・未発効を素通しする（fail-open）。
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    it(`nowSeconds=${bad} は exp 付き JWT を INVALID_DID で拒否する（fail-closed）`, () => {
      const did = buildDidJwt(p256, { payloadOverrides: { exp: NOW - 1 } });
      expect(() => resolveDidJwt(did, bad)).toThrow(
        expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
      );
    });

    it(`nowSeconds=${bad} は nbf 付き JWT を INVALID_DID で拒否する（fail-closed）`, () => {
      const did = buildDidJwt(p256, { payloadOverrides: { nbf: NOW + 1 } });
      expect(() => resolveDidJwt(did, bad)).toThrow(
        expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
      );
    });
  }
});

describe('MethodJwt ライフサイクル非対応', () => {
  const method = new MethodJwt();

  it('create は METHOD_NOT_SUPPORTED', async () => {
    await expect(
      method.create({ keyType: 'P-256', publicKey: new Uint8Array(33) }),
    ).rejects.toMatchObject({ code: ErrorCodes.METHOD_NOT_SUPPORTED });
  });

  it('update は METHOD_NOT_SUPPORTED', async () => {
    await expect(method.update('did:jwt:x', {})).rejects.toMatchObject({
      code: ErrorCodes.METHOD_NOT_SUPPORTED,
    });
  });

  it('deactivate は METHOD_NOT_SUPPORTED', async () => {
    await expect(method.deactivate('did:jwt:x')).rejects.toMatchObject({
      code: ErrorCodes.METHOD_NOT_SUPPORTED,
    });
  });
});
