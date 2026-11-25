/**
 * ファサード `receiveCredential` の SD-JWT VC の Credential Request。
 *
 * SD-JWT VC は型を `vct` の 1 値で持つ（旧 Draft 形。draft-13 Annex A.3。1.0 Final の要求に `vct` は無い）。この `vct` は
 * Offer の `credential_configuration_ids[0]`（Metadata を引くための不透明なキー）ではなく、
 * **Issuer が `credential_configurations_supported[id].vct` で告知した値**でなければならない。
 *
 * 本ファイルが固定するのは「Issuer Metadata の告知 → `IssuerEndpoints.credentialVcts` →
 * Credential Request の本文」という配線である（`oid4vci.credential-sd-jwt-vct.test.ts` は
 * `requestCredential` に `vct` を渡したときの本文だけを見ており、この連結は通らない）。
 *
 * 実害: walt.id issuer-api は `findMatchingIssuanceRequest` でこの `vct` を告知値と突き合わせる。
 * 送らない / 違う値を送ると発行セッションに紐づかず HTTP 400 になる。
 */

import { describe, expect, test } from 'bun:test';
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

/** 受領する format。`facadeDeps` の既定は SD-JWT VC ではないため明示する。 */
const SD_JWT_VC_FORMAT = 'dc+sd-jwt';

/** Issuer が告知する `vct`。configuration id（`CONFIGURATION_ID`）とは**別の値**にして取り違えを検出する。 */
const ADVERTISED_VCT = 'https://issuer.example.com/credentials/diploma';

function credentialBody(stub: {
  callTo(url: string): { body?: string } | undefined;
}): Record<string, unknown> {
  return JSON.parse(stub.callTo(CREDENTIAL_URL)?.body ?? '{}') as Record<string, unknown>;
}

/** `credential_configurations_supported` に `vct` を告知する Issuer Metadata。 */
function metadataAdvertisingVct(): Response {
  return issuerMetadataResponse({
    credential_configurations_supported: {
      [CONFIGURATION_ID]: { format: 'dc+sd-jwt', vct: ADVERTISED_VCT },
    },
  });
}

function stubFor(metadata: () => Response, vct: string) {
  return createStubFetch({
    [ISSUER_METADATA_URL]: metadata,
    [TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: () =>
      json({ credential: buildSdJwtVc({ vct, claims: { degree: 'Laurea' } }) }),
  });
}

describe('receiveCredential: SD-JWT VC は告知された vct を Credential Request に載せる', () => {
  test('Metadata が vct を告知していれば、その値を送り credential_definition を送らない', async () => {
    const stub = stubFor(metadataAdvertisingVct, ADVERTISED_VCT);
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { format: SD_JWT_VC_FORMAT }),
    );
    const body = credentialBody(stub);
    expect(body.vct).toBe(ADVERTISED_VCT);
    expect(Object.hasOwn(body, 'credential_definition')).toBe(false);
    // 不透明なキーである configuration id を `vct` として送っていないこと。
    expect(body.vct).not.toBe(CONFIGURATION_ID);
  });

  test('Metadata が vct を告知しなければ、従来どおり credential_definition を送る', async () => {
    // 告知が無い Issuer（旧 Draft 系）を壊さないための fail-open。ここが静かに fail-closed 化すると、
    // `vct` を解さない Issuer からの受領が一律で落ちる。
    const stub = stubFor(() => issuerMetadataResponse(), CONFIGURATION_ID);
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, { format: SD_JWT_VC_FORMAT }),
    );
    const body = credentialBody(stub);
    expect(Object.hasOwn(body, 'vct')).toBe(false);
    expect(body.credential_definition).toEqual({ type: [CONFIGURATION_ID] });
  });
});

describe('receiveCredential: authorization_code 経路も告知された vct を載せる', () => {
  // `viaAuthorizationCode` → `receiveCredentialViaAuthorizationCode` → `requestCredential` の 3 段で `vct` を
  // 受け渡す。どれか 1 段で落ちると pre-authorized_code 経路のテストは通ったまま本経路だけ従来形に戻る。
  function authzStub(metadata: () => Response) {
    return createStubFetch({
      [ISSUER_METADATA_URL]: metadata,
      [AS_METADATA_URL]: () => asMetadataResponse(),
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: () =>
        json({ credential: buildSdJwtVc({ vct: ADVERTISED_VCT, claims: { degree: 'Laurea' } }) }),
    });
  }

  test('Metadata が vct を告知していれば、その値を送り credential_definition を送らない', async () => {
    const stub = authzStub(() =>
      issuerMetadataResponse({
        authorization_servers: [AS],
        credential_configurations_supported: {
          [CONFIGURATION_ID]: { format: 'dc+sd-jwt', vct: ADVERTISED_VCT },
        },
      }),
    );
    await receiveCredential(
      authorizationCodeOfferURI(),
      authorizationCodeDeps(stub, { format: SD_JWT_VC_FORMAT }),
    );
    const body = credentialBody(stub);
    expect(body.vct).toBe(ADVERTISED_VCT);
    expect(Object.hasOwn(body, 'credential_definition')).toBe(false);
  });

  test('Metadata が vct を告知しなければ、従来どおり credential_definition を送る', async () => {
    const stub = authzStub(() => issuerMetadataResponse({ authorization_servers: [AS] }));
    await receiveCredential(
      authorizationCodeOfferURI(),
      authorizationCodeDeps(stub, { format: SD_JWT_VC_FORMAT }),
    );
    const body = credentialBody(stub);
    expect(Object.hasOwn(body, 'vct')).toBe(false);
    expect(body.credential_definition).toEqual({ type: [CONFIGURATION_ID] });
  });
});
