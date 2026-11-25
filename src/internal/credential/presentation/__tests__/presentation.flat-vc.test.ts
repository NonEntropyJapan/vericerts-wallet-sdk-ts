/**
 * VP に内包された VC 2.0 系 JWT-VC（`vc` 非包み・`validFrom` / `validUntil`）の検証。
 *
 * `jwtVcTypesOf`（`credential-entry/entry-result.ts`）が flat 形の `type` を返さないと、Trusted Issuer List の
 * **種別制限**（`credentialTypes`）が効かず、権限のない種別を発行した発行者が信頼済みになる。
 * 検証本体（`verifyCredential`）と種別取得が同じ表現判定（`vc/jwt-vc-body.ts`）を共有していることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import type { TrustedIssuerList } from '../../../trusted-issuer/types.js';
import type { EmbeddedCredentialKeyResolver } from '../credential-results.js';
import { issuePresentation } from '../issue.js';
import { verifyPresentation } from '../presentation.js';
import { VC_V2_CONTEXT } from '../vp.js';
import { FIXTURES, sampleVp, signerFor } from './presentation.fixtures.js';

const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const ISSUER_DID = 'did:example:issuer';
const ISSUER_ALG = 'ES256K' as const;
const HOLDER_ALG = 'ES256' as const;
const issuerKeyResolver: EmbeddedCredentialKeyResolver = () => ({
  publicKeyJwk: FIXTURES[ISSUER_ALG].jwk,
});
const holderKey = { key: { publicKeyJwk: FIXTURES[HOLDER_ALG].jwk }, allowUnbound: true } as const;

const iso = (sec: number): string => new Date(sec * 1000).toISOString();

/** 発行者鍵で署名した、walt.id 形（`vc` 非包み）の内包用 JWT-VC。 */
function flatVc(type: string[], overrides: Record<string, unknown> = {}): string {
  const payload = {
    iss: ISSUER_DID,
    sub: 'did:example:holder',
    '@context': [VC_V2_CONTEXT],
    id: 'urn:uuid:flat-1',
    type,
    issuer: ISSUER_DID,
    credentialSubject: { id: 'did:example:holder' },
    validFrom: iso(NOW - 3600),
    validUntil: iso(NOW + 3600),
    jti: 'urn:uuid:flat-1',
    exp: NOW + 3600,
    iat: NOW - 3600,
    nbf: NOW - 3600,
    ...overrides,
  };
  const header = Buffer.from(JSON.stringify({ alg: ISSUER_ALG, typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = signerFor(ISSUER_ALG).sign(new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${Buffer.from(signature).toString('base64url')}`;
}

function vpWith(entry: string): string {
  return issuePresentation(sampleVp({ verifiableCredential: [entry] }), signerFor(HOLDER_ALG), {
    nowSeconds: NOW,
  });
}

function til(credentialTypes?: string[]): TrustedIssuerList {
  return {
    id: 'til-1',
    type: 'TrustedIssuerList',
    version: 'TSLv1',
    listOperator: 'did:example:operator',
    listName: 'Test TIL',
    issuedAt: '2025-01-01T00:00:00Z',
    trustedIssuers: [
      { id: ISSUER_DID, name: ISSUER_DID, ...(credentialTypes ? { credentialTypes } : {}) },
    ],
  };
}

const verifyEntry = (entry: string, trustedIssuerList?: TrustedIssuerList) =>
  verifyPresentation(vpWith(entry), {
    ...holderKey,
    nowSeconds: NOW,
    credentialKey: issuerKeyResolver,
    ...(trustedIssuerList ? { trustedIssuerList } : {}),
  }).credentialResults[0];

describe('verifyPresentation: 内包された VC 2.0 系 JWT-VC（vc 非包み）', () => {
  it('署名・envelope 突合を通り valid になる', () => {
    const result = verifyEntry(flatVc(['VerifiableCredential', 'UniversityDegree']));
    expect(result?.valid).toBe(true);
    expect(result?.issuerDID).toBe(ISSUER_DID);
  });

  it('種別制限（credentialTypes）が効く: 権限のない種別は信頼済みにならず、権限のある種別は信頼済み', () => {
    const university = til(['UniversityDegree']);
    const denied = verifyEntry(
      flatVc(['VerifiableCredential', 'BankAccountCredential']),
      university,
    );
    expect(denied?.valid).toBe(true);
    expect(denied?.isTrustedIssuer).toBe(false);

    const allowed = verifyEntry(flatVc(['VerifiableCredential', 'UniversityDegree']), university);
    expect(allowed?.isTrustedIssuer).toBe(true);
  });

  it('envelope と本体の不一致（iss ≠ issuer）は valid:false（3002）', () => {
    const result = verifyEntry(flatVc(['VerifiableCredential'], { iss: 'did:example:attacker' }));
    expect(result?.valid).toBe(false);
    expect(result?.errors).toEqual(['3002']);
  });
});
