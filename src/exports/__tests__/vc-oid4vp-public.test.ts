import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../common.js';
import {
  assertTimeClaims,
  assertVerifiableCredentialV2Members,
  createPrivateKeySigner,
  decodeCompactJws,
  issueCredential,
  jwtVcBodyOf,
  resolveClockSkewSeconds,
  type VerifiableCredential,
  verifyCredential,
  verifyPresentation,
  verifyWithJwk,
} from '../credential.js';
import { getP256PublicKey } from '../keymanager.js';
import {
  createDcqlWorkBudget,
  createPresentation,
  evaluateDcql,
  findMatchingCredentialIndexes,
  parsePresentationRequest,
  type QueryableCredential,
} from '../oid4vp.js';

const CLIENT_ID = 'https://verifier.example.com';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const HOLDER_DID = 'did:example:holder';
const ISSUER_KEY = new Uint8Array(32).fill(11);
const HOLDER_KEY = new Uint8Array(32).fill(12);
const issuerSigner = createPrivateKeySigner(ISSUER_KEY, 'ES256');
const holderSigner = createPrivateKeySigner(HOLDER_KEY, 'ES256');

function publicJwk(privateKey: Uint8Array) {
  const point = getP256PublicKey(privateKey, false);
  return {
    kty: 'EC' as const,
    crv: 'P-256',
    x: Buffer.from(point.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(point.subarray(33, 65)).toString('base64url'),
  };
}

function credential(id: string, name: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'UniversityDegree'],
    issuer: 'did:example:issuer',
    credentialSubject: { name },
    issuanceDate: '2025-01-01T00:00:00Z',
    id,
  };
}

function requestUri(): string {
  const query = {
    credentials: [
      {
        id: 'degree',
        format: 'jwt_vc_json',
        claims: [{ path: ['credentialSubject', 'name'], values: ['Bob'] }],
      },
    ],
  };
  const params = new URLSearchParams({
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: `${CLIENT_ID}/callback`,
    nonce: NONCE,
    state: 'state',
    dcql_query: JSON.stringify(query),
  });
  return `openid4vp://?${params.toString()}`;
}

function errorCode(operation: () => unknown): string | undefined {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    return (error as VericertsError).code;
  }
  return undefined;
}

describe('public /credential VC contract', () => {
  test('decode and VC 2.0 shape inspection do not claim to verify a signature', () => {
    const flat = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { name: 'Bob' },
      validFrom: '2025-01-01T00:00:00Z',
    };
    expect(assertVerifiableCredentialV2Members(flat).validFrom).toBe(flat.validFrom);
    expect(jwtVcBodyOf(flat)).toEqual({ form: 'flat', body: flat });
    expect(jwtVcBodyOf({ vc: flat })).toEqual({ form: 'wrapped', body: flat });

    const signed = issueCredential(credential('urn:vc:bob', 'Bob'), issuerSigner);
    const decoded = decodeCompactJws(signed);
    const issuerJwk = publicJwk(ISSUER_KEY);
    expect(verifyWithJwk('ES256', decoded, issuerJwk)).toBe(true);

    const changed = { ...decoded, signature: Uint8Array.from(decoded.signature) };
    changed.signature[0] = (changed.signature[0] ?? 0) ^ 1;
    expect(changed.payload.iss).toBe('did:example:issuer');
    expect(verifyWithJwk('ES256', changed, issuerJwk)).toBe(false);
    expect(verifyCredential(signed, { key: { publicKeyJwk: issuerJwk } }).payload.iss).toBe(
      'did:example:issuer',
    );
    expect(() => decodeCompactJws('not-a-jws')).toThrow(VericertsError);
  });

  test('time claims use the same public clock-skew profile and fail closed', () => {
    const skew = resolveClockSkewSeconds('vc', undefined);
    expect(skew).toBe(120);
    expect(() => assertTimeClaims({ exp: 1_000 }, 999, 0)).not.toThrow();
    expect(errorCode(() => assertTimeClaims({ exp: 1_000 }, 1_000, 0))).toBe(ErrorCodes.VC_EXPIRED);
  });
});

describe('public /oid4vp DCQL contract', () => {
  test('the same budget is consumed across both evaluators and exhaustion is irreversible', () => {
    const query = { credentials: [{ id: 'degree', format: 'jwt_vc_json' }] };
    const credentials: QueryableCredential[] = [
      { id: 'a', format: 'jwt_vc_json', claims: {} },
      { id: 'b', format: 'dc+sd-jwt', claims: {} },
      { id: 'c', format: 'jwt_vc_json', claims: {} },
    ];
    const budget = createDcqlWorkBudget();
    budget.remaining = 4;
    expect(findMatchingCredentialIndexes(query, credentials, budget)).toEqual([0, 2]);
    expect(budget.remaining).toBe(1);
    expect(evaluateDcql(query, credentials.slice(0, 1), budget)).toHaveLength(1);
    expect(budget.remaining).toBe(0);
    expect(errorCode(() => evaluateDcql(query, credentials.slice(0, 1), budget))).toBe(
      ErrorCodes.OID4VP_REQUEST_PARSE_FAILED,
    );
    expect(budget.exhausted).toBe(true);
    expect(budget.remaining).toBe(0);
    expect(findMatchingCredentialIndexes(query, credentials)).toEqual([0, 2]);
    expect(evaluateDcql(query, credentials)).toHaveLength(2);
  });
});

describe('public /oid4vp presentation contract', () => {
  test('uses the selected VC, holder binding, audience, nonce and original issuer-signed JWT', async () => {
    const bob = credential('urn:vc:bob', 'Bob');
    const alice = credential('urn:vc:alice', 'Alice');
    const raw = issueCredential(bob, issuerSigner);
    const request = await parsePresentationRequest(requestUri());
    const loaCalls: string[][] = [];

    const result = await createPresentation(
      request,
      [bob],
      [alice, bob],
      holderSigner,
      HOLDER_DID,
      {
        rawCredentials: new Map([[bob.id as string, raw]]),
        checkLoa: (selected) => {
          loaCalls.push(selected.map((vc) => vc.id as string));
        },
      },
    );

    expect(loaCalls).toEqual([['urn:vc:bob']]);
    expect(result.holder).toBe(HOLDER_DID);
    expect(result.verifiableCredential).toEqual([raw]);
    expect(verifyCredential(raw, { key: { publicKeyJwk: publicJwk(ISSUER_KEY) } })).toBeDefined();
    const verified = verifyPresentation(result.jwt, {
      key: { publicKeyJwk: publicJwk(HOLDER_KEY) },
      expectedAudience: CLIENT_ID,
      expectedNonce: NONCE,
    });
    expect(verified.payload.iss).toBe(HOLDER_DID);
    expect(verified.payload.aud).toBe(CLIENT_ID);
    expect(verified.payload.nonce).toBe(NONCE);
    expect(verified.presentation.verifiableCredential).toEqual([raw]);
  });

  test('rejects an unmatched selection, absent nonce and invalid raw credential mapping', async () => {
    const bob = credential('urn:vc:bob', 'Bob');
    const alice = credential('urn:vc:alice', 'Alice');
    const request = await parsePresentationRequest(requestUri());
    await expect(
      createPresentation(request, [alice], [alice], holderSigner, HOLDER_DID),
    ).rejects.toMatchObject({ code: ErrorCodes.VC_REQUIREMENT_MISMATCH });

    const { nonce: _nonce, ...withoutNonce } = request;
    await expect(
      createPresentation(withoutNonce as typeof request, [bob], [bob], holderSigner, HOLDER_DID),
    ).rejects.toMatchObject({ code: ErrorCodes.OID4VP_REQUEST_PARSE_FAILED });

    await expect(
      createPresentation(request, [bob], [bob], holderSigner, HOLDER_DID, {
        rawCredentials: new Map([[bob.id as string, '']]),
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.VC_SCHEMA_INVALID });
  });
});
