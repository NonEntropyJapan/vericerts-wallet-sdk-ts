/**
 * `checkDomainLinkageClaims`（DLC 固有の条件: self-issued・`credentialSubject.origin` 一致）の表現別テスト。
 *
 * JWT-VC には VC 本体が `vc` claim に入る形（wrapped）と、payload 自体が VC 本体の形（flat。VC 2.0 系。
 * walt.id が出す形）がある（`vc/jwt-vc-body.ts`）。`verifyCredentialWith` は両方を受理するため、
 * ここが `vc` claim しか読まないと、署名検証を通った flat の DLC が常に `origin_mismatch` になる。
 */

import { describe, expect, it } from 'bun:test';
import { checkDomainLinkageClaims } from '../linked-did-claims.js';

const DID = 'did:example:holder';
const ORIGIN = 'https://example.com';

const body = (origin: unknown): Record<string, unknown> => ({
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'DomainLinkageCredential'],
  issuer: DID,
  credentialSubject: { id: DID, origin },
});

/** VC 1.1 系: 本体は `vc` claim、envelope の `iss` / `sub` は本体の写し。 */
const wrapped = (
  origin: unknown,
  claims: Record<string, unknown> = {},
): Record<string, unknown> => ({
  iss: DID,
  sub: DID,
  vc: { ...body(origin), issuanceDate: '2020-01-01T00:00:00.000Z' },
  ...claims,
});

/** VC 2.0 系: `vc` で包まず payload 自体が本体。 */
const flat = (origin: unknown, claims: Record<string, unknown> = {}): Record<string, unknown> => ({
  iss: DID,
  sub: DID,
  ...body(origin),
  validFrom: '2020-01-01T00:00:00.000Z',
  ...claims,
});

describe.each([
  ['VC 1.1 系（vc 包み）', wrapped],
  ['VC 2.0 系（vc 非包み）', flat],
])('checkDomainLinkageClaims: %s', (_name, build) => {
  it('self-issued かつ origin 一致なら valid', () => {
    expect(checkDomainLinkageClaims(build(ORIGIN), ORIGIN)).toEqual({ did: DID, valid: true });
  });

  it('origin 不一致は origin_mismatch', () => {
    expect(checkDomainLinkageClaims(build('https://other.example'), ORIGIN)).toEqual({
      did: DID,
      valid: false,
      error: 'origin_mismatch',
    });
  });

  it('origin が文字列でなければ origin_mismatch', () => {
    expect(checkDomainLinkageClaims(build(['https://example.com']), ORIGIN)).toEqual({
      did: DID,
      valid: false,
      error: 'origin_mismatch',
    });
  });

  it('iss ≠ sub は not_self_issued（表現に依らず先に判定する）', () => {
    expect(checkDomainLinkageClaims(build(ORIGIN, { iss: 'did:example:other' }), ORIGIN)).toEqual({
      did: DID,
      valid: false,
      error: 'not_self_issued',
    });
  });
});

describe('checkDomainLinkageClaims: 本体の所在', () => {
  it('vc claim も @context も無い payload は origin_mismatch', () => {
    expect(checkDomainLinkageClaims({ iss: DID, sub: DID }, ORIGIN)).toEqual({
      did: DID,
      valid: false,
      error: 'origin_mismatch',
    });
  });

  it('vc claim があれば @context を併せ持っていても vc 内を読む（トップレベルの origin は無視する）', () => {
    const payload = { ...flat(ORIGIN), vc: { ...body('https://other.example') } };
    expect(checkDomainLinkageClaims(payload, ORIGIN)).toEqual({
      did: DID,
      valid: false,
      error: 'origin_mismatch',
    });
  });

  it('Object.prototype の汚染値を本体として読まない（flat 判定は own の @context のみ）', () => {
    const polluted = Object.prototype as unknown as Record<string, unknown>;
    polluted['@context'] = ['https://www.w3.org/ns/credentials/v2'];
    polluted.credentialSubject = { origin: ORIGIN };
    try {
      expect(checkDomainLinkageClaims({ iss: DID, sub: DID }, ORIGIN)).toEqual({
        did: DID,
        valid: false,
        error: 'origin_mismatch',
      });
    } finally {
      delete polluted['@context'];
      delete polluted.credentialSubject;
    }
  });
});
