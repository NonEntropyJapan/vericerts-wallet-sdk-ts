/**
 * ファサード `receiveCredential` の OID4VCI 1.0 Final 形 Credential Request / Response。
 *
 * 1.0 Final の Issuer は `credential_configuration_id` + `proofs` を要求し、`credentials: [{ credential }]` で
 * 返す。`credentialRequestVersion: '1.0'` を明示した受領が pre-authorized_code / authorization_code の
 * 両経路でこの形になること、未指定は旧 Draft 形のままであることを固定する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../../errors.js';
import { receiveCredential } from '../../receive.js';
import {
  AS,
  AS_METADATA_URL,
  asMetadataResponse,
  authorizationCodeDeps,
  authorizationCodeOfferURI,
  buildSdJwtVc,
  CONFIGURATION_ID,
  CREDENTIAL_URL,
  createStubFetch,
  facadeDeps,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  json,
  PAR_URL,
  parResponse,
  preAuthorizedOfferURI,
  TOKEN_URL,
  tokenResponse,
} from '../facade-fixtures.js';

const FINAL_RESPONSE = (): Response =>
  json({
    credentials: [
      { credential: buildSdJwtVc({ vct: CONFIGURATION_ID, claims: { degree: 'Laurea' } }) },
    ],
  });

function credentialBody(stub: { callTo(url: string): { body?: string } | undefined }): object {
  return JSON.parse(stub.callTo(CREDENTIAL_URL)?.body ?? '{}') as object;
}

describe('receiveCredential: credentialRequestVersion "1.0"', () => {
  test('pre-authorized_code: 1.0 形で要求し、credentials[] の VC を受領する', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: FINAL_RESPONSE,
    });
    const vc = await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { credentialRequestVersion: '1.0' }),
    );
    expect(vc.claims.degree).toBe('Laurea');
    const body = credentialBody(stub) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['credential_configuration_id', 'proofs']);
    expect(body.credential_configuration_id).toBe(CONFIGURATION_ID);
    expect((body.proofs as { jwt: string[] }).jwt).toHaveLength(1);
  });

  test('authorization_code: 1.0 形で要求し、credentials[] の VC を受領する', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
      [AS_METADATA_URL]: () => asMetadataResponse(),
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: FINAL_RESPONSE,
    });
    const vc = await receiveCredential(
      authorizationCodeOfferURI(),
      authorizationCodeDeps(stub, { credentialRequestVersion: '1.0' }),
    );
    expect(vc.claims.degree).toBe('Laurea');
    expect(Object.keys(credentialBody(stub)).sort()).toEqual([
      'credential_configuration_id',
      'proofs',
    ]);
  });

  test('未指定は旧 Draft 形のまま', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: FINAL_RESPONSE,
    });
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    expect(Object.keys(credentialBody(stub))).toEqual(['format', 'credential_definition', 'proof']);
  });

  test('未知の credentialRequestVersion は HTTP 前に fail-closed', async () => {
    const stub = createStubFetch({});
    await expect(
      receiveCredential(
        preAuthorizedOfferURI(),
        facadeDeps(stub, { credentialRequestVersion: '2.0' as unknown as '1.0' }),
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(stub.calls).toEqual([]);
  });
});
