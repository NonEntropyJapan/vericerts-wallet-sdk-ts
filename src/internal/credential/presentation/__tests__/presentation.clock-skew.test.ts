/**
 * JWT-VP のクロックスキュー境界テスト（実鍵・モック禁止）。
 *
 * JWT-VP の時計ずれの既定値と上限は、ともに 30 秒である。JWT-VC の 120 秒より厳しい。
 * - `exp` は `now - skew >= exp` で期限切れ（境界値ちょうどを拒否）。
 * - `nbf` は `now + skew < nbf` で未有効（境界値ちょうどを受理）。
 * - `iat` は `iat > now + skew` で `CLOCK_SKEW_EXCEEDED`（4014）。過去方向は無制限。
 *
 * `issuePresentation` は `nbf` / `iat` を出力しないため、境界値の payload は実鍵で手組み署名する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import { verifyPresentation } from '../presentation.js';
import { VC_V2_CONTEXT, type VerifiablePresentation } from '../vp.js';

/** テスト用の固定秘密鍵。 */
const HOLDER_KEY = new Uint8Array(32).fill(23);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const HOLDER_JWK = toJwk(getP256PublicKey(HOLDER_KEY, false), 'P-256');
const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256');
const AUDIENCE = 'https://verifier.example';
const NONCE = 'n-1';

/** 固定の現在時刻 N（2026-01-01T00:00:00Z）。 */
const N = 1_767_225_600;
/** JWT-VP の既定 = 上限キャップ。 */
const CAP = 30;

/** 検証側に渡す期待値（バインド必須モード）。 */
const EXPECTED = {
  key: { publicKeyJwk: HOLDER_JWK },
  expectedAudience: AUDIENCE,
  expectedNonce: NONCE,
  nowSeconds: N,
} as const;

/** サンプル VP。 */
function sampleVp(): VerifiablePresentation {
  return {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiablePresentation'],
    holder: 'did:example:holder',
    verifiableCredential: ['eyJhbGciOiJFUzI1NiJ9.vc-payload.sig'],
    id: 'urn:uuid:vp-clock-skew',
  };
}

/** 任意の時刻クレームを載せた JWT-VP を実鍵で組み立てる。 */
function signVpWithTimes(times: Record<string, unknown>): string {
  const b64u = (text: string): string => Buffer.from(text).toString('base64url');
  const payload = {
    iss: 'did:example:holder',
    aud: AUDIENCE,
    nonce: NONCE,
    vp: sampleVp(),
    ...times,
  };
  const signingInput = `${b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT' }))}.${b64u(
    JSON.stringify(payload),
  )}`;
  const signature = HOLDER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

describe('JWT-VP のクロックスキュー境界（既定 30s）', () => {
  it('exp = N - 30（境界ちょうど）は VC_EXPIRED（3024）', () => {
    expect(() => verifyPresentation(signVpWithTimes({ exp: N - CAP }), EXPECTED)).toThrow(
      new VericertsError(ErrorCodes.VC_EXPIRED),
    );
  });

  it('exp = N - 29（境界 +1s）は検証成功する', () => {
    const result = verifyPresentation(signVpWithTimes({ exp: N - CAP + 1 }), EXPECTED);
    expect(result.payload.exp).toBe(N - CAP + 1);
  });

  it('nbf = N + 30（境界ちょうど）は検証成功する', () => {
    const result = verifyPresentation(signVpWithTimes({ nbf: N + CAP }), EXPECTED);
    expect(result.payload.nbf).toBe(N + CAP);
  });

  it('nbf = N + 31（境界 +1s）は VC_NOT_YET_VALID（3025）', () => {
    expect(() => verifyPresentation(signVpWithTimes({ nbf: N + CAP + 1 }), EXPECTED)).toThrow(
      new VericertsError(ErrorCodes.VC_NOT_YET_VALID),
    );
  });

  it('iat = N + 30（境界ちょうど）は検証成功する', () => {
    const result = verifyPresentation(signVpWithTimes({ iat: N + CAP }), EXPECTED);
    expect(result.payload.iat).toBe(N + CAP);
  });

  it('iat = N + 31（境界 +1s）は CLOCK_SKEW_EXCEEDED（4014）', () => {
    expect(() => verifyPresentation(signVpWithTimes({ iat: N + CAP + 1 }), EXPECTED)).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });

  it('iat の過去方向は無制限（N - 86400 でも検証成功する）', () => {
    // 過去方向の鮮度は `maxAgeSeconds` / `exp` の責務で、クロックスキュープロファイルは関与しない。
    const result = verifyPresentation(signVpWithTimes({ iat: N - 86_400 }), EXPECTED);
    expect(result.payload.iat).toBe(N - 86_400);
  });
});
