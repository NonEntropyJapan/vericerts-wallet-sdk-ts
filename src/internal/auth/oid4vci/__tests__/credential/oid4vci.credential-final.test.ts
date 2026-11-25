/**
 * Credential Request / Response の OID4VCI 1.0 Final 形（§8.2 / §8.3）。
 *
 * 回帰観点:
 * - `credentialConfigurationId` 指定時は `{ credential_configuration_id, proofs: { jwt: [..] } }` だけを送り、
 *   `format` / `credential_definition` / 旧 `proof` を混ぜない。未指定は従来の旧 Draft 形のまま。
 * - 応答の `credentials: [{ credential }]`（ちょうど 1 要素）を受ける。旧 `credential` も従来どおり受ける。
 * - `credentials` と `transaction_id` / 旧 `credential` の併存、空配列・複数要素・非 object 要素は 8020。
 */

import { afterEach, describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import type { FetchLike } from '../../../../fetch-di.js';
import { type RequestCredentialOptions, requestCredential } from '../../oid4vci.js';

const CREDENTIAL_URL = 'https://issuer.example.com/credential';
const PROOF_JWT = 'header.payload.sig';

function stub(response: unknown): { fetchImpl: FetchLike; bodies: unknown[] } {
  const bodies: unknown[] = [];
  const fetchImpl: FetchLike = async (_url, init) => {
    bodies.push(JSON.parse(String(init.body)));
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  return { fetchImpl, bodies };
}

function options(overrides: Partial<RequestCredentialOptions>): RequestCredentialOptions {
  return {
    credentialEndpoint: CREDENTIAL_URL,
    accessToken: 'access-token-value',
    format: 'dc+sd-jwt',
    credentialDefinition: { type: ['UniversityDegree'] },
    proofJwt: PROOF_JWT,
    ...overrides,
  };
}

afterEach(() => {
  delete (Object.prototype as unknown as Record<string, unknown>).credentialConfigurationId;
});

describe('requestCredential: 要求本文の形', () => {
  test('credentialConfigurationId 指定時は 1.0 Final 形だけを送る', async () => {
    const { fetchImpl, bodies } = stub({ credentials: [{ credential: 'vc-1' }] });
    await requestCredential(
      options({ fetchImpl, credentialConfigurationId: 'UniversityDegreeJWT' }),
    );
    expect(bodies).toEqual([
      { credential_configuration_id: 'UniversityDegreeJWT', proofs: { jwt: [PROOF_JWT] } },
    ]);
  });

  test('未指定は旧 Draft 形のまま（format / credential_definition / proof）', async () => {
    const { fetchImpl, bodies } = stub({ credential: 'vc-1' });
    await requestCredential(options({ fetchImpl }));
    expect(bodies).toEqual([
      {
        format: 'dc+sd-jwt',
        credential_definition: { type: ['UniversityDegree'] },
        proof: { proof_type: 'jwt', jwt: PROOF_JWT },
      },
    ]);
  });

  test('空文字の credentialConfigurationId は HTTP 前に 8020', async () => {
    const { fetchImpl, bodies } = stub({ credential: 'vc-1' });
    await expect(
      requestCredential(options({ fetchImpl, credentialConfigurationId: '' })),
    ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    expect(bodies).toEqual([]);
  });

  test('Object.prototype.credentialConfigurationId の汚染値で 1.0 形へ化けない', async () => {
    Object.defineProperty(Object.prototype, 'credentialConfigurationId', {
      configurable: true,
      value: 'polluted',
    });
    const { fetchImpl, bodies } = stub({ credential: 'vc-1' });
    await requestCredential(options({ fetchImpl }));
    expect(Object.keys(bodies[0] as object)).toEqual(['format', 'credential_definition', 'proof']);
  });
});

describe('requestCredential: 応答の形（§8.3）', () => {
  test('credentials: [{ credential }] を受領する', async () => {
    const { fetchImpl } = stub({ credentials: [{ credential: 'vc-final' }], c_nonce: 'n' });
    await expect(requestCredential(options({ fetchImpl }))).resolves.toEqual({
      status: 'issued',
      credential: 'vc-final',
      cNonce: 'n',
    });
  });

  test.each([
    ['transaction_id との併存', { credentials: [{ credential: 'vc' }], transaction_id: 'tx' }],
    ['旧 credential との併存', { credentials: [{ credential: 'vc' }], credential: 'vc' }],
    ['空配列', { credentials: [] }],
    ['複数要素', { credentials: [{ credential: 'a' }, { credential: 'b' }] }],
    ['配列でない', { credentials: { credential: 'vc' } }],
    ['要素が object でない', { credentials: ['vc'] }],
    ['credential が文字列でない', { credentials: [{ credential: 1 }] }],
    ['credential が空文字', { credentials: [{ credential: '' }] }],
  ])('%s は 8020', async (_name, response) => {
    const { fetchImpl } = stub(response);
    await expect(requestCredential(options({ fetchImpl }))).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
    });
  });
});
