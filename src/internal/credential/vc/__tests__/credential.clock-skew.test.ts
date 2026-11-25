/**
 * JWT-VC のクロックスキュー境界テスト（実鍵・モック禁止）。
 *
 * JWT-VC の時計ずれの既定値と上限は、ともに 120 秒である。
 * - `exp` は `now - skew >= exp` で期限切れ（境界値ちょうどを拒否）。
 * - `nbf` は `now + skew < nbf` で未有効（境界値ちょうどを受理）。
 * - `iat` は `iat > now + skew` で `CLOCK_SKEW_EXCEEDED`（4014）。過去方向は無制限。
 * - `clockSkewSeconds: 0` の `exp` / `nbf` 判定は本オプション導入前と同一（`iat` は 0 でも評価される）。
 * - `iat` は `exp` / `nbf` より先に評価する（時計が進んだ端末には 4014 を返す）。
 *
 * 発行器（`issueCredential`）は `iat` を出力しないため、`iat` 系は発行済み JWT-VC の payload へ
 * `iat` を注入して実鍵で再署名する（時刻評価は envelope binding より前に走るため受理経路は壊れない）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { issueCredential } from '../issue.js';
import { createPrivateKeySigner } from '../signer.js';
import type { VerifiableCredential } from '../vc.js';
import { verifyCredential } from '../verify.js';

/** テスト用の固定秘密鍵。 */
const ISSUER_KEY = new Uint8Array(32).fill(21);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const KEY = { publicKeyJwk: ISSUER_JWK } as const;

/** 固定の現在時刻 N（2026-01-01T00:00:00Z）。 */
const N = 1_767_225_600;
/** JWT-VC の既定 = 上限キャップ。 */
const CAP = 120;

/** エポック秒を ISO 8601 へ変換する（`isoToNumericDate` と往復一致する精度）。 */
function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

/** `nbf` / `exp` を指定した JWT-VC を実鍵で発行する。 */
function issueWithTimes(times: { nbf: number; exp?: number }): string {
  const vc: VerifiableCredential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: iso(times.nbf),
    ...(times.exp !== undefined ? { expirationDate: iso(times.exp) } : {}),
    id: 'urn:uuid:clock-skew',
  };
  return issueCredential(vc, ISSUER_SIGNER, { nowSeconds: N });
}

/** 発行済み JWT-VC の payload の `iat` を差し替え（`undefined` なら削除）、同じ実鍵で再署名する。 */
function withIat(jwt: string, iat: unknown): string {
  const b64u = (text: string): string => Buffer.from(text).toString('base64url');
  const payload = JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString());
  // `JSON.stringify` は値が undefined のキーを落とすため、`iat` 欠落の JWT-VC もこれで作れる。
  const signingInput = `${b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT' }))}.${b64u(
    JSON.stringify({ ...payload, iat }),
  )}`;
  const signature = ISSUER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/** 時刻評価が通る土台の JWT-VC（nbf は十分過去、exp は十分未来）。 */
function validJwt(): string {
  return issueWithTimes({ nbf: N - 10_000, exp: N + 10_000 });
}

describe('JWT-VC の exp / nbf クロックスキュー境界（既定 120s）', () => {
  it('exp = N - 120（境界ちょうど）は VC_EXPIRED（3024）', () => {
    const jwt = issueWithTimes({ nbf: N - 10_000, exp: N - CAP });
    expect(() => verifyCredential(jwt, { key: KEY, nowSeconds: N })).toThrow(
      new VericertsError(ErrorCodes.VC_EXPIRED),
    );
  });

  it('exp = N - 119（境界 +1s）は検証成功する', () => {
    const jwt = issueWithTimes({ nbf: N - 10_000, exp: N - CAP + 1 });
    expect(verifyCredential(jwt, { key: KEY, nowSeconds: N }).payload.iss).toBe(
      'did:example:issuer',
    );
  });

  it('nbf = N + 120（境界ちょうど）は検証成功する', () => {
    const jwt = issueWithTimes({ nbf: N + CAP, exp: N + 10_000 });
    expect(verifyCredential(jwt, { key: KEY, nowSeconds: N }).payload.nbf).toBe(N + CAP);
  });

  it('nbf = N + 121（境界 +1s）は VC_NOT_YET_VALID（3025）', () => {
    const jwt = issueWithTimes({ nbf: N + CAP + 1, exp: N + 10_000 });
    expect(() => verifyCredential(jwt, { key: KEY, nowSeconds: N })).toThrow(
      new VericertsError(ErrorCodes.VC_NOT_YET_VALID),
    );
  });

  it('exp = N でも clockSkewSeconds: 0 なら VC_EXPIRED（3024。導入前と同一挙動）', () => {
    const jwt = issueWithTimes({ nbf: N - 10_000, exp: N });
    expect(() => verifyCredential(jwt, { key: KEY, nowSeconds: N, clockSkewSeconds: 0 })).toThrow(
      new VericertsError(ErrorCodes.VC_EXPIRED),
    );
  });
});

describe('JWT-VC の iat クロックスキュー境界（既定 120s）', () => {
  it('iat = N + 120（境界ちょうど）は検証成功する', () => {
    const jwt = withIat(validJwt(), N + CAP);
    expect(verifyCredential(jwt, { key: KEY, nowSeconds: N }).payload.iat).toBe(N + CAP);
  });

  it('iat = N + 121（境界 +1s）は CLOCK_SKEW_EXCEEDED（4014）', () => {
    const jwt = withIat(validJwt(), N + CAP + 1);
    expect(() => verifyCredential(jwt, { key: KEY, nowSeconds: N })).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });

  it('clockSkewSeconds: 30 では iat = N + 30 を受理する', () => {
    const jwt = withIat(validJwt(), N + 30);
    const result = verifyCredential(jwt, { key: KEY, nowSeconds: N, clockSkewSeconds: 30 });
    expect(result.payload.iat).toBe(N + 30);
  });

  it('clockSkewSeconds: 30 では iat = N + 31 を CLOCK_SKEW_EXCEEDED（4014）で拒否する', () => {
    const jwt = withIat(validJwt(), N + 31);
    expect(() => verifyCredential(jwt, { key: KEY, nowSeconds: N, clockSkewSeconds: 30 })).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });

  it('iat 型不正（非数値）は VC_SCHEMA_INVALID（3002）', () => {
    const jwt = withIat(validJwt(), 'not-a-number');
    expect(() => verifyCredential(jwt, { key: KEY, nowSeconds: N })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('iat が無い JWT-VC は従来どおり検証成功する（後方互換）', () => {
    // `issueCredential` は `iat` を必ず出力するため、旧 Issuer 発行相当の payload を作って検証する。
    const result = verifyCredential(withIat(validJwt(), undefined), { key: KEY, nowSeconds: N });
    expect(result.payload.iat).toBeUndefined();
  });

  it('iat と nbf が同時に超過した場合は iat を優先し CLOCK_SKEW_EXCEEDED（4014）', () => {
    // 時計が進んだ端末では nbf 判定（3025）より iat 判定（4014）の方が診断的なため順序を固定する。
    const jwt = withIat(issueWithTimes({ nbf: N + CAP + 1, exp: N + 10_000 }), N + CAP + 1);
    expect(() => verifyCredential(jwt, { key: KEY, nowSeconds: N })).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });
});
