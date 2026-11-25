/**
 * `verifyEmbeddedCredentials` の入力キー省略 + `Object.prototype` 汚染。
 *
 * 型が必須キー（`T | undefined` / `number`）でも、公開 ESM/CJS を使う JS 消費者はどのキーでも省略できる。省略したキーを
 * プロトタイプ鎖で読むと、汚染値が「呼び出し側が渡した値」として採用され、失効 VC・別 Verifier 宛 KB-JWT・委任なしの提示が
 * 受理される。汚染前後で結果が変わらないことを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { verifyEmbeddedCredentials } from '../../../../../exports/credential.js';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { computeSdHash, KB_JWT_TYP } from '../../../sdjwt/key-binding.js';
import { createSdJwt } from '../../../sdjwt/sdjwt.js';
import { issueCredential } from '../../../vc/issue.js';
import type { VerificationResult } from '../../credential-results.js';
import { VC_V2_CONTEXT } from '../../vp.js';
import { FIXTURES, signerFor } from '../presentation.fixtures.js';

const key = () => ({ publicKeyJwk: FIXTURES.ES256K.jwk });
const b64 = (text: string) => Buffer.from(text).toString('base64url');
const ISSUED = Math.floor(Date.parse('2020-01-01T00:00:00Z') / 1000);
const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);

/** 失効済み（exp = 2021-01-01）の JWT-VC。 */
const expiredJwtVc = issueCredential(
  {
    '@context': [VC_V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2020-01-01T00:00:00Z',
    expirationDate: '2021-01-01T00:00:00Z',
    id: 'urn:uuid:1',
  } as never,
  signerFor('ES256K'),
  { nowSeconds: ISSUED },
);

/** 別 Verifier（aud）・別セッション（nonce）宛の KB-JWT 付き SD-JWT VC。 */
function kbJwtForOtherVerifier(): string {
  const presentation = createSdJwt(signerFor('ES256K'), {
    vct: 'https://example.com/id',
    disclosureClaims: ['name'],
    claims: { name: 'Alice' },
    salts: { name: 's' },
    issuer: 'did:example:issuer',
    nowSeconds: NOW,
    cnf: { jwk: FIXTURES.ES256.jwk },
  });
  const header = b64(JSON.stringify({ alg: 'ES256', typ: KB_JWT_TYP }));
  const payload = b64(
    JSON.stringify({
      aud: 'https://evil.example',
      nonce: 'attacker-nonce',
      sd_hash: computeSdHash(presentation),
      iat: NOW,
    }),
  );
  const signature = Buffer.from(
    signerFor('ES256').sign(new TextEncoder().encode(`${header}.${payload}`)),
  ).toString('base64url');
  return `${presentation}${header}.${payload}.${signature}`;
}

/** 結果の正規化（時刻・順序に依存する値を含めない）。 */
const summarize = (results: readonly VerificationResult[]) =>
  results.map((r) => ({ valid: r.valid, errors: r.errors, isExpired: r.isExpired }));

describe('verifyEmbeddedCredentials: 入力キー省略 + Object.prototype 汚染', () => {
  it('nowSeconds を省略した入力で、失効済み JWT-VC が汚染値（過去時刻）で valid にならない', () => {
    const input = { credentialKey: key, holderDID: 'did:example:holder' } as never;
    const clean = summarize(verifyEmbeddedCredentials([expiredJwtVc], input));
    expect(clean[0]?.valid).toBe(false);
    const polluted = withPollutedPrototype({ nowSeconds: ISSUED + 100 }, () =>
      summarize(verifyEmbeddedCredentials([expiredJwtVc], input)),
    );
    expect(polluted).toEqual(clean);
  });

  it('audience / nonce を省略した requireHolderBinding で、別 Verifier 宛 KB-JWT が汚染値で valid にならない', () => {
    const kb = kbJwtForOtherVerifier();
    const input = {
      credentialKey: key,
      nowSeconds: NOW,
      holderDID: 'did:example:holder',
      requireHolderBinding: true,
    } as never;
    const clean = summarize(verifyEmbeddedCredentials([kb], input));
    expect(clean[0]?.valid).toBe(false);
    expect(clean[0]?.errors).toEqual(['3012']);
    const polluted = withPollutedPrototype(
      { audience: 'https://evil.example', nonce: 'attacker-nonce' },
      () => summarize(verifyEmbeddedCredentials([kb], input)),
    );
    expect(polluted).toEqual(clean);
  });

  it('requireHolderBinding を省略した入力で、汚染値 true によって突合・KB-JWT 必須化が有効にならない', () => {
    const input = { credentialKey: key, nowSeconds: ISSUED } as never;
    const clean = summarize(verifyEmbeddedCredentials([expiredJwtVc], input));
    const polluted = withPollutedPrototype({ requireHolderBinding: true }, () =>
      summarize(verifyEmbeddedCredentials([expiredJwtVc], input)),
    );
    expect(polluted).toEqual(clean);
    expect(clean[0]?.valid).toBe(true);
  });

  it('clockSkewSeconds / issuerTrust を省略した入力で、汚染値のスキュー・信頼設定が採用されない', () => {
    // 失効 1 年後。汚染値の skew（約 1 年）が採用されれば valid に見えてしまう。
    const input = {
      credentialKey: key,
      nowSeconds: Date.parse('2021-06-01T00:00:00Z') / 1000,
    } as never;
    const clean = summarize(verifyEmbeddedCredentials([expiredJwtVc], input));
    expect(clean[0]?.valid).toBe(false);
    const polluted = withPollutedPrototype(
      { clockSkewSeconds: 60 * 60 * 24 * 365, issuerTrust: { trusted: true } },
      () => summarize(verifyEmbeddedCredentials([expiredJwtVc], input)),
    );
    expect(polluted).toEqual(clean);
  });

  it('trustedIssuerList を省略した入力で、汚染値のリストで isTrustedIssuer が true にならない', () => {
    const input = { credentialKey: key, nowSeconds: ISSUED } as never;
    const trusted = (results: readonly VerificationResult[]) =>
      results.map((r) => r.isTrustedIssuer);
    const clean = trusted(verifyEmbeddedCredentials([expiredJwtVc], input));
    const polluted = withPollutedPrototype(
      { trustedIssuerList: [{ did: 'did:example:issuer', credentialTypes: [] }] },
      () => trusted(verifyEmbeddedCredentials([expiredJwtVc], input)),
    );
    expect(polluted).toEqual(clean);
  });
});
