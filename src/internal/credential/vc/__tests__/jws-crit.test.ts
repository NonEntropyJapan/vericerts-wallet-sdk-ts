/**
 * JWS `crit` ヘッダ（RFC 7515 §4.1.11）の全検証経路での拒否テスト。
 *
 * SDK が理解する拡張は 0 個のため、`alg` と署名が正しくても `crit` を持つ JWS は無効。
 * 実鍵（P-256）で署名した JWS を各経路へ渡し、`crit` なしは受理・ありは拒否されることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes } from '../../../errors.js';
import {
  b64uText,
  buildDidJwt,
  NOW,
  p256Fixture,
} from '../../../identity/jwt/__tests__/jwt-fixtures.js';
import { resolveDidJwt } from '../../../identity/jwt/method-jwt.js';
import { verifyStatusListToken } from '../../../issuer/status-list-token-verify.js';
import { verifySdJwt } from '../../sdjwt/verify.js';
import { decodeCompactJws } from '../jws.js';
import { verifyCredential } from '../verify.js';

const key = p256Fixture(new Uint8Array(32).fill(7));
const CRIT = {
  crit: ['https://evil.example/must-understand'],
  'https://evil.example/must-understand': true,
};

/** 任意ヘッダ・ペイロードを実鍵で署名したコンパクト JWS。 */
function signJws(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const input = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = key.sign(new TextEncoder().encode(input));
  return `${input}.${base64urlnopad.encode(sig)}`;
}

const header = (extra: Record<string, unknown> = {}) => ({ alg: 'ES256', typ: 'JWT', ...extra });

describe('JWS crit の拒否', () => {
  it('did:jwt: crit 付きは INVALID_DID、crit なしは解決できる', () => {
    expect(() => resolveDidJwt(buildDidJwt(key, { headerOverrides: CRIT }), NOW)).toThrow(
      expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
    );
    expect(resolveDidJwt(buildDidJwt(key), NOW).verificationMethod?.length).toBe(1);
  });

  it('did:jwt: 空配列・非配列の crit も拒否する（存在自体を拒否）', () => {
    for (const crit of [[], 'x', null]) {
      expect(() => resolveDidJwt(buildDidJwt(key, { headerOverrides: { crit } }), NOW)).toThrow(
        expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
      );
    }
  });

  it('decodeCompactJws（JAR / DPoP / presentation 等の共通デコード）は crit を拒否する', () => {
    expect(() => decodeCompactJws(signJws(header(CRIT), { iss: 'x' }))).toThrow(
      expect.objectContaining({ code: ErrorCodes.INVALID_DID }),
    );
    expect(decodeCompactJws(signJws(header(), { iss: 'x' })).payload.iss).toBe('x');
  });

  it('verifyCredential は crit 付き JWT-VC を SIG_INVALID（3010）で拒否する', () => {
    const jwt = signJws(header(CRIT), { iss: 'did:example:i', nbf: NOW, vc: {} });
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: key.jwk as never }, nowSeconds: NOW }),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.SIG_INVALID }));
  });

  it('verifySdJwt は crit 付き Issuer-signed JWT を SIG_INVALID（3010）で拒否する', () => {
    const jwt = signJws(header(CRIT), { iss: 'did:example:i', vct: 'urn:x', iat: NOW });
    expect(() => verifySdJwt(`${jwt}~`, { issuerKey: key.jwk as never, nowSeconds: NOW })).toThrow(
      expect.objectContaining({ code: ErrorCodes.SIG_INVALID }),
    );
  });

  it('verifyStatusListToken は crit 付きトークンを拒否する', () => {
    const jwt = signJws(header(CRIT), {
      sub: 'https://i.example/s/1',
      status_list: { bits: 1, lst: '' },
    });
    expect(() => verifyStatusListToken(jwt, 'https://i.example/s/1', key.jwk as never)).toThrow();
  });
});
