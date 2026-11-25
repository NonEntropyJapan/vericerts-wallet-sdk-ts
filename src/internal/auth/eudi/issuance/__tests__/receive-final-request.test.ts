/**
 * EUDI `receivePIDCredential` / `receiveEAACredential` の OID4VCI 1.0 Final 形 Credential Request / Response
 * `credentialRequestVersion: '1.0'` で `credential_configuration_id` + `proofs` を送り、
 * `credentials: [{ credential }]` の応答から受領できること、未指定は旧 Draft 形のままであることを固定する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { PID_VCT } from '../../../../eudi/pid/index.js';
import { receivePIDCredential } from '../receive.js';
import {
  AS_METADATA_URL,
  asMetadataResponse,
  buildSdJwtVc,
  CREDENTIAL_URL,
  createStubFetch,
  defaultOfferURI,
  jsonResponse,
  METADATA_URL,
  metadataResponse,
  receiveDeps,
  TOKEN_URL,
  tokenResponse,
  VALID_PID_CLAIMS,
} from './issuance-fixtures.js';

function finalStub() {
  const sdJwt = buildSdJwtVc({ claims: VALID_PID_CLAIMS });
  return createStubFetch({
    [METADATA_URL]: metadataResponse,
    [AS_METADATA_URL]: () => asMetadataResponse(),
    [TOKEN_URL]: tokenResponse,
    [CREDENTIAL_URL]: () => jsonResponse({ credentials: [{ credential: sdJwt }] }),
  });
}

function requestBody(stub: ReturnType<typeof createStubFetch>): Record<string, unknown> {
  const call = stub.calls.find((c) => c.url === CREDENTIAL_URL);
  return JSON.parse(call?.body ?? '{}') as Record<string, unknown>;
}

describe('receivePIDCredential: credentialRequestVersion "1.0"', () => {
  test('1.0 形で要求し credentials[] の PID を受領する', async () => {
    const stub = finalStub();
    const pid = await receivePIDCredential(defaultOfferURI(), {
      ...receiveDeps(stub.fetchImpl),
      credentialRequestVersion: '1.0',
    });
    expect(pid.vct).toBe(PID_VCT);
    const body = requestBody(stub);
    expect(Object.keys(body).sort()).toEqual(['credential_configuration_id', 'proofs']);
    expect(body.credential_configuration_id).toBe(PID_VCT);
  });

  test('未指定は旧 Draft 形（credentials[] 応答は受領できる）', async () => {
    const stub = finalStub();
    await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
    // 旧 Draft 形。SD-JWT VC なので型は `vct` で伝える。
    expect(Object.keys(requestBody(stub))).toEqual(['format', 'vct', 'proof']);
  });

  test('未知の credentialRequestVersion は HTTP 前に 8020', async () => {
    const stub = finalStub();
    await expect(
      receivePIDCredential(defaultOfferURI(), {
        ...receiveDeps(stub.fetchImpl),
        credentialRequestVersion: '2.0' as unknown as '1.0',
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    expect(stub.calls).toEqual([]);
  });
});
