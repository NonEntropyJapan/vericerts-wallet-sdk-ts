/**
 * vc-verify カテゴリのコンフォーマンスベクタ（JWT-VC 部分）。
 * 検証には生成済みの token 文字列を使うため、ECDSA 署名を再生成する必要はない。
 */

import { issueCredential } from '../../src/internal/credential/vc/issue.js';
import { createPrivateKeySigner } from '../../src/internal/credential/vc/signer.js';
import type { VerifiableCredential } from '../../src/internal/credential/vc/vc.js';
import { verifyCredential } from '../../src/internal/credential/vc/verify.js';
import type { Case } from './shared.js';
import { errorCodeOf } from './shared.js';

const NOW = 1_767_225_600; // 2026-01-01T00:00:00Z
const ISSUANCE = '2025-12-01T00:00:00Z';
const EXPIRATION = '2027-01-01T00:00:00Z';
const PAST_EXPIRATION = '2025-12-15T00:00:00Z'; // before NOW -> expired
const FUTURE_ISSUANCE = '2026-06-01T00:00:00Z'; // after NOW -> not yet valid

function baseVc(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:jwk:test-issuer',
    credentialSubject: { id: 'did:jwk:test-subject', name: 'Conformance Test' },
    issuanceDate: ISSUANCE,
    expirationDate: EXPIRATION,
    ...overrides,
  };
}

function tamperSignature(jwt: string): string {
  const parts = jwt.split('.');
  const sig = Buffer.from(parts[2], 'base64url');
  sig[0] ^= 0xff; // flip a byte in the signature
  parts[2] = sig.toString('base64url');
  return parts.join('.');
}

function forceAlgNone(jwt: string): string {
  const [, payload, signature] = jwt.split('.');
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  return `${header}.${payload}.${signature}`;
}

export function getJwtVcCases(): Case[] {
  const cases: Case[] = [];
  const p256Priv = new Uint8Array(32).fill(11);
  const signer = createPrivateKeySigner(p256Priv, 'ES256');
  const verifyOpts = (nowSeconds: number) => ({
    key: { publicKeyJwk: signer.publicKeyJwk },
    nowSeconds,
  });

  const validJwt = issueCredential(baseVc(), signer, { nowSeconds: NOW - 1000 });
  cases.push({
    id: 'jwt-vc-verify-valid-es256',
    category: 'vc-verify',
    description: 'JWT-VC (ES256) verifies successfully within validity window',
    input: {
      format: 'jwt-vc',
      token: validJwt,
      issuerPublicKeyJwk: signer.publicKeyJwk,
      nowSeconds: NOW,
    },
    expected: { ok: true },
  });

  const expiredJwt = issueCredential(baseVc({ expirationDate: PAST_EXPIRATION }), signer, {
    nowSeconds: NOW - 2000,
  });
  cases.push({
    id: 'jwt-vc-verify-expired',
    category: 'vc-verify',
    description: 'JWT-VC rejects a credential past its expirationDate',
    input: {
      format: 'jwt-vc',
      token: expiredJwt,
      issuerPublicKeyJwk: signer.publicKeyJwk,
      nowSeconds: NOW,
    },
    expected: {
      ok: false,
      errorCode: errorCodeOf(() => verifyCredential(expiredJwt, verifyOpts(NOW))),
    },
  });

  const notYetValidJwt = issueCredential(baseVc({ issuanceDate: FUTURE_ISSUANCE }), signer, {
    nowSeconds: NOW - 1000,
  });
  cases.push({
    id: 'jwt-vc-verify-not-yet-valid',
    category: 'vc-verify',
    description: 'JWT-VC rejects a credential before its issuanceDate (nbf)',
    input: {
      format: 'jwt-vc',
      token: notYetValidJwt,
      issuerPublicKeyJwk: signer.publicKeyJwk,
      nowSeconds: NOW,
    },
    expected: {
      ok: false,
      errorCode: errorCodeOf(() => verifyCredential(notYetValidJwt, verifyOpts(NOW))),
    },
  });

  const tamperedJwt = tamperSignature(validJwt);
  cases.push({
    id: 'jwt-vc-verify-tampered-signature',
    category: 'vc-verify',
    description: 'JWT-VC rejects a tampered signature',
    input: {
      format: 'jwt-vc',
      token: tamperedJwt,
      issuerPublicKeyJwk: signer.publicKeyJwk,
      nowSeconds: NOW,
    },
    expected: {
      ok: false,
      errorCode: errorCodeOf(() => verifyCredential(tamperedJwt, verifyOpts(NOW))),
    },
  });

  const algNoneJwt = forceAlgNone(validJwt);
  cases.push({
    id: 'jwt-vc-verify-alg-none-rejected',
    category: 'vc-verify',
    description: 'JWT-VC rejects alg=none',
    input: {
      format: 'jwt-vc',
      token: algNoneJwt,
      issuerPublicKeyJwk: signer.publicKeyJwk,
      nowSeconds: NOW,
    },
    expected: {
      ok: false,
      errorCode: errorCodeOf(() => verifyCredential(algNoneJwt, verifyOpts(NOW))),
    },
  });

  return cases;
}
