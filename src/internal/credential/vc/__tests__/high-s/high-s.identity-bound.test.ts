/**
 * 署名バイト列が識別子・重複判定キーになる経路は high-S を受理しないことの固定。
 *
 * JWS 検証共通経路（`verifyWithJwk`）は ES256 の high-S を既定で受理するが、
 * - DPoP proof: 呼び出し側が proof 文字列を重複判定キーに使い得る（`dpop-verify.ts` の署名長検査と同じ理由）。
 * - did:jwt: DID 文字列が JWT（署名含む）の base64url そのもの＝署名が識別子の一部であり、`s` と `n - s` の
 *   2 通りが同一鍵・同一 payload に対して別 DID になる。
 * いずれも `ALG_SPECS[alg].verify` に `allowHighS: false` を明示して low-S を強制する。
 */

import { describe, expect, it } from 'bun:test';
import { createDpopProof } from '../../../../auth/dpop/dpop.js';
import { verifyDpopProof } from '../../../../auth/dpop/dpop-verify.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { buildDidJwt, NOW, p256Fixture } from '../../../../identity/jwt/__tests__/jwt-fixtures.js';
import { resolveDidJwt } from '../../../../identity/jwt/method-jwt.js';
import { HIGH_S_FIXTURES, toHighS } from './high-s.fixtures.js';

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  return undefined;
}

describe('DPoP proof は ES256 high-S を受理しない', () => {
  const fx = HIGH_S_FIXTURES.ES256;
  const proof = createDpopProof(
    { htm: 'POST', htu: 'https://api.example.com/mcp', nowSeconds: NOW },
    fx.signer,
  );
  const opts = { htm: 'POST', htu: 'https://api.example.com/mcp', nowSeconds: NOW } as const;

  it('low-S の proof は検証できる', () => {
    expect(verifyDpopProof(proof, opts).jti.length).toBeGreaterThan(0);
  });

  it('high-S の proof は DPOP_SIGNATURE_INVALID（4081）', () => {
    expect(codeOf(() => verifyDpopProof(toHighS('ES256', proof), opts))).toBe(
      ErrorCodes.DPOP_SIGNATURE_INVALID,
    );
  });
});

describe('did:jwt は ES256 high-S を受理しない', () => {
  const key = p256Fixture(new Uint8Array(32).fill(7));
  const did = buildDidJwt(key);

  it('low-S の did:jwt は解決できる', () => {
    expect(resolveDidJwt(did, NOW).id).toBe(did);
  });

  it('署名を high-S に差し替えた did:jwt は INVALID_DID（2001）', () => {
    const jwt = Buffer.from(did.slice('did:jwt:'.length), 'base64url').toString('utf-8');
    const highS = `did:jwt:${Buffer.from(toHighS('ES256', jwt)).toString('base64url')}`;
    expect(codeOf(() => resolveDidJwt(highS, NOW))).toBe(ErrorCodes.INVALID_DID);
  });
});
