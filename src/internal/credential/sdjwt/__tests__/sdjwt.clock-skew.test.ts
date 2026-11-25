/**
 * SD-JWT VC / KB-JWT のクロックスキュー境界テスト（実鍵・モック禁止）。
 *
 * Issuer-signed JWT と KB-JWT にそれぞれの時計ずれ上限が適用されることを検証する。
 * - Issuer-signed JWT は SD-JWT VC 行（既定 = 上限キャップ 120s）で評価する。
 * - KB-JWT は KB-JWT 行（30s）で評価し、`clockSkewSeconds` は `min(指定値, 30)` にクランプされる
 *   （より厳しい KB-JWT プロファイルが常に優先され、120 を指定しても KB は緩まない）。
 * - KB-JWT の未来 `iat` 判定は `maxAgeSeconds` の指定有無に依存しない（4014）。一方、鮮度
 *   （`iat` 欠落・非有限・古すぎ）は従来どおり `maxAgeSeconds` 指定時のみ 3012 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import type { CredentialAlg } from '../../vc/jws.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import { createSdJwt, selectDisclosures } from '../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../verify.js';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(29);
const HOLDER_KEY = new Uint8Array(32).fill(31);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const HOLDER_JWK = toJwk(getSecp256k1PublicKey(HOLDER_KEY, false), 'secp256k1');
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256K' as CredentialAlg);
const VCT = 'https://example.com/credentials/identity';
const NONCE = 'n-1';
const AUD = 'https://verifier.example';

/** 固定の現在時刻 N（2026-01-01T00:00:00Z）。 */
const N = 1_767_225_600;
/** KB-JWT の上限キャップ / SD-JWT VC（Issuer JWT）の上限キャップ。 */
const KB_CAP = 30;
const VC_CAP = 120;

/** cnf 付き SD-JWT を発行する（`times` は開示対象外の平文クレームとして issuer payload に残る）。 */
function issue(times: Record<string, unknown> = {}): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    cnf: { jwk: HOLDER_JWK },
    disclosureClaims: ['name'],
    claims: { name: 'Alice', ...times },
    salts: { name: 'salt-name' },
    nowSeconds: N,
  });
}

/** 指定 iat の KB-JWT を付与した提示部を作る。 */
function boundWithIat(iat: number): string {
  return addKeyBinding(selectDisclosures(issue(), ['name']), HOLDER_SIGNER, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: iat,
  });
}

/**
 * 任意の（`iat` 欠落・非数値を含む）KB-JWT payload を実鍵で手組みして提示部に連結する。
 * `addKeyBinding` は `iat` を数値で必ず出力するため、欠落・型不正の検証にはこちらを使う。
 */
function boundWithRawPayload(extra: Record<string, unknown>): string {
  const presented = selectDisclosures(issue(), ['name']);
  const b64u = (t: string): string => Buffer.from(t).toString('base64url');
  // sd_hash は addKeyBinding と同一計算にするため、一度正規の KB を付けて取り出す。
  const sample = addKeyBinding(presented, HOLDER_SIGNER, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: N,
  });
  const sampleKb = sample.slice(sample.lastIndexOf('~') + 1);
  const samplePayload = JSON.parse(
    Buffer.from(sampleKb.split('.')[1] ?? '', 'base64url').toString(),
  );
  const header = b64u(JSON.stringify({ alg: 'ES256K', typ: 'kb+jwt' }));
  const payload = b64u(
    JSON.stringify({ nonce: NONCE, aud: AUD, sd_hash: samplePayload.sd_hash, ...extra }),
  );
  const signingInput = `${header}.${payload}`;
  const sig = HOLDER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${presented}${signingInput}.${Buffer.from(sig).toString('base64url')}`;
}

/** KB 検証の共通オプション（`maxAgeSeconds` は個別に足す）。 */
const KB_BASE = { issuerKey: ISSUER_JWK, audience: AUD, nonce: NONCE, nowSeconds: N } as const;

describe('KB-JWT の未来 iat（maxAgeSeconds 非依存 / 既定クランプ 30s）', () => {
  it('iat = N + 30 は maxAgeSeconds 未指定でも検証成功する', () => {
    expect(verifySdJwt(boundWithIat(N + KB_CAP), KB_BASE).keyBindingVerified).toBe(true);
  });

  it('iat = N + 31 は maxAgeSeconds 未指定でも CLOCK_SKEW_EXCEEDED（4014）', () => {
    // 未来 iat の判定は maxAgeSeconds のゲート下ではなく、KB-JWT 検証時に常に走る。
    expect(() => verifySdJwt(boundWithIat(N + KB_CAP + 1), KB_BASE)).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });

  it('iat = N + 31 は maxAgeSeconds 指定時も CLOCK_SKEW_EXCEEDED（4014。3012 ではない）', () => {
    expect(() =>
      verifySdJwt(boundWithIat(N + KB_CAP + 1), { ...KB_BASE, maxAgeSeconds: 300 }),
    ).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });

  it('iat 型不正（非数値）は maxAgeSeconds 指定時に HOLDER_BIND_MISMATCH（3012。従来どおり）', () => {
    const bound = boundWithRawPayload({ iat: 'not-a-number' });
    expect(() => verifySdJwt(bound, { ...KB_BASE, maxAgeSeconds: 300 })).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  it('iat 欠落は maxAgeSeconds 未指定なら従来どおり検証成功する', () => {
    expect(verifySdJwt(boundWithRawPayload({}), KB_BASE).keyBindingVerified).toBe(true);
  });

  it('now - iat > maxAgeSeconds（古すぎる提示）は HOLDER_BIND_MISMATCH（3012。従来どおり）', () => {
    expect(() => verifySdJwt(boundWithIat(N - 400), { ...KB_BASE, maxAgeSeconds: 300 })).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  // 時計を -5 分遅らせた Wallet からの SD-JWT VC 提示（KB-JWT 付き）。
  // 過去方向の iat は本プロファイルの対象外であり、鮮度は maxAgeSeconds だけが担う。
  it('now - iat = 300（-5 分）でも maxAgeSeconds 未指定なら検証成功する', () => {
    expect(verifySdJwt(boundWithIat(N - 300), KB_BASE).keyBindingVerified).toBe(true);
  });
});

describe('KB-JWT のスキュークランプ min(clockSkewSeconds, 30)', () => {
  it('clockSkewSeconds: 120 でも KB-JWT は 30s へクランプされる（+30 受理 / +31 拒否）', () => {
    // 最重要: VC 側の 120s を指定しても KB-JWT が 120s まで緩むことはない。
    const accepted = verifySdJwt(boundWithIat(N + KB_CAP), {
      ...KB_BASE,
      clockSkewSeconds: VC_CAP,
    });
    expect(accepted.keyBindingVerified).toBe(true);
    expect(() =>
      verifySdJwt(boundWithIat(N + KB_CAP + 1), { ...KB_BASE, clockSkewSeconds: VC_CAP }),
    ).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });

  it('clockSkewSeconds: 10（30 より厳しい）はそのまま KB-JWT に効く（+10 受理 / +11 拒否）', () => {
    const accepted = verifySdJwt(boundWithIat(N + 10), { ...KB_BASE, clockSkewSeconds: 10 });
    expect(accepted.keyBindingVerified).toBe(true);
    expect(() => verifySdJwt(boundWithIat(N + 11), { ...KB_BASE, clockSkewSeconds: 10 })).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
  });
});

describe('SD-JWT Issuer JWT は VC 階層（120s）で評価する', () => {
  it('exp = N - 120（境界ちょうど）は VC_EXPIRED（3024）', () => {
    expect(() =>
      verifySdJwt(issue({ exp: N - VC_CAP }), { issuerKey: ISSUER_JWK, nowSeconds: N }),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));
  });

  it('exp = N - 119（境界 +1s）は検証成功する（KB の 30s ではなく 120s が効く）', () => {
    const result = verifySdJwt(issue({ exp: N - VC_CAP + 1 }), {
      issuerKey: ISSUER_JWK,
      nowSeconds: N,
    });
    expect(result.claims.name).toBe('Alice');
  });
});
