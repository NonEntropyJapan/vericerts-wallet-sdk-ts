/**
 * KB-JWT 鮮度検証（`assertKeyBinding`）が非有限の `nowSeconds` / `maxAgeSeconds` で fail-open しないことの
 * 回帰テスト（実鍵・モック禁止）。
 *
 * `iat > now + skew` / `now - iat > maxAge` は NaN で常に `false` になり、未来 `iat`・古い KB-JWT
 * （リプレイ）を素通しする。修正前は例外が出ず、このテストが落ちる。4015 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import type { CredentialAlg } from '../../vc/jws.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import { computeSdHash } from '../key-binding.js';
import { assertKeyBinding } from '../key-binding-verify.js';
import { createSdJwt, parseSdJwt, selectDisclosures } from '../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../verify.js';

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
const N = 1_767_225_600;
const NON_FINITE = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY] as const;
const CLOCK_INVALID = new VericertsError(ErrorCodes.CLOCK_SKEW_OPTION_INVALID);

/** 指定 iat の KB-JWT を付与した提示部（`withoutKb` は sd_hash 計算対象）。 */
function bound(iat: number): string {
  const issued = createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    cnf: { jwk: HOLDER_JWK },
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 'salt-name' },
    nowSeconds: N,
  });
  return addKeyBinding(selectDisclosures(issued, ['name']), HOLDER_SIGNER, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: iat,
  });
}

/** `assertKeyBinding` を直接呼ぶ（`verifySdJwt` 経由だと Issuer JWT の時刻検証が先に走るため）。 */
function check(sdJwt: string, opts: Record<string, unknown>): void {
  const parts = parseSdJwt(sdJwt);
  const kb = parts.keyBinding as string;
  const withoutKb = sdJwt.slice(0, sdJwt.length - kb.length);
  const cnf = { jwk: HOLDER_JWK };
  assertKeyBinding(
    kb,
    cnf,
    computeSdHash(withoutKb),
    { issuerKey: ISSUER_JWK, audience: AUD, nonce: NONCE, ...opts },
    30,
  );
}

describe('assertKeyBinding: 非有限の nowSeconds は fail-closed（4015）', () => {
  it('有限時刻では未来 iat（+31）を 4014 で拒否し、正規の iat は通す', () => {
    expect(() => check(bound(N + 31), { nowSeconds: N })).toThrow(
      new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED),
    );
    expect(() => check(bound(N), { nowSeconds: N })).not.toThrow();
  });

  for (const bad of NON_FINITE) {
    it(`nowSeconds = ${bad}: 未来 iat の KB-JWT を通さない`, () => {
      expect(() => check(bound(N + 100_000), { nowSeconds: bad })).toThrow(CLOCK_INVALID);
    });

    it(`nowSeconds = ${bad}: maxAgeSeconds 指定の古い KB-JWT（リプレイ）を通さない`, () => {
      expect(() => check(bound(N - 100_000), { nowSeconds: bad, maxAgeSeconds: 300 })).toThrow(
        CLOCK_INVALID,
      );
    });
  }
});

describe('maxAgeSeconds が非有限なら鮮度検査を無効化しない（4015）', () => {
  it('有限の maxAgeSeconds では古すぎる KB-JWT を 3012 で拒否する', () => {
    expect(() => check(bound(N - 400), { nowSeconds: N, maxAgeSeconds: 300 })).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  for (const bad of NON_FINITE) {
    it(`maxAgeSeconds = ${bad}: 古い KB-JWT を通さない（修正前は NaN / Infinity で受理された）`, () => {
      expect(() => check(bound(N - 100_000), { nowSeconds: N, maxAgeSeconds: bad })).toThrow(
        CLOCK_INVALID,
      );
    });
  }

  it('verifySdJwt 経由でも maxAgeSeconds = Infinity は 4015', () => {
    expect(() =>
      verifySdJwt(bound(N - 100_000), {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        nowSeconds: N,
        maxAgeSeconds: Number.POSITIVE_INFINITY,
      }),
    ).toThrow(CLOCK_INVALID);
  });
});
