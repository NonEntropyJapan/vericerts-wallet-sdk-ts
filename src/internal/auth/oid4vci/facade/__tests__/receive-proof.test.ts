/**
 * `receiveCredential` が Credential Request に載せる DPoP proof の `ath`・JWT Proof の `aud` / `nonce`
 *
 * - DPoP: Credential Endpoint 用の `createDpopProof` は access_token を受け取り、`ath`（RFC 9449 §4.2）を
 *   載せられる。PAR / Token 用は access_token がまだ無いので受け取らない。
 * - `aud`: Credential Issuer Identifier（OID4VCI 1.0 §8.2.1.1）。Credential Endpoint の URL ではない。
 * - `nonce`: Nonce Endpoint → Token Response の `c_nonce`（旧 Draft）→ 省略の順で解決する（§7 / §8.2）。
 */

import { describe, expect, test } from 'bun:test';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { createDpopProof } from '../../../dpop/dpop.js';
import { computeAth } from '../../../dpop/dpop-common.js';
import { HOLDER_PRIVATE_KEY } from '../../../eudi/issuance/__tests__/issuance-fixtures.js';
import { generateProofJWT } from '../../oid4vci.js';
import type { DpopProofContext } from '../../oid4vci-credential-dpop.js';
import { receiveCredential } from '../receive.js';
import {
  ACCESS_TOKEN,
  C_NONCE,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  facadeDeps,
  ISSUER,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  json,
  preAuthorizedOfferURI,
  TOKEN_URL,
  tokenResponse,
} from './facade-fixtures.js';

const NONCE_URL = `${ISSUER}/nonce`;
const NONCE_ENDPOINT_VALUE = 'nonce-endpoint-value';

/** JWT のペイロードを復号する。 */
function payloadOf(jwt: string): Record<string, unknown> {
  const part = jwt.split('.')[1] ?? '';
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** Credential Request 本文の JWT Proof ペイロード。 */
function proofClaims(body: string | undefined): Record<string, unknown> {
  const parsed = JSON.parse(body ?? '{}') as { proof: { jwt: string } };
  return payloadOf(parsed.proof.jwt);
}

/** `token_endpoint` を載せた旧 Draft 形式の Issuer Metadata + 任意の Token Response。 */
function stubWith(options: {
  tokenResponse: () => Response;
  nonceEndpoint?: boolean;
}): ReturnType<typeof createStubFetch> {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () =>
      issuerMetadataResponse(options.nonceEndpoint === true ? { nonce_endpoint: NONCE_URL } : {}),
    [NONCE_URL]: () => json({ c_nonce: NONCE_ENDPOINT_VALUE }),
    [TOKEN_URL]: options.tokenResponse,
    [CREDENTIAL_URL]: credentialResponse,
  });
}

describe('receiveCredential: Credential Endpoint 用 DPoP proof に ath を載せられる', () => {
  test('createDpopProof は Credential Endpoint 用の呼び出しにだけ access_token を受け取る', async () => {
    const stub = stubWith({ tokenResponse: tokenResponse('DPoP') });
    const calls: Array<{ htu: string; ctx: DpopProofContext | undefined }> = [];
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, {
        createDpopProof: (htu, ctx) => {
          calls.push({ htu, ctx });
          return `proof-for-${htu}`;
        },
      }),
    );
    expect(calls).toEqual([
      { htu: TOKEN_URL, ctx: undefined },
      { htu: CREDENTIAL_URL, ctx: { accessToken: ACCESS_TOKEN } },
    ]);
  });

  test('中継した access_token で作った proof は computeAth(access_token) と一致する ath を持つ', async () => {
    const stub = stubWith({ tokenResponse: tokenResponse('DPoP') });
    const signer = createPrivateKeySigner(HOLDER_PRIVATE_KEY, 'ES256');
    await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, {
        createDpopProof: (htu, ctx) =>
          createDpopProof(
            {
              htm: 'POST',
              htu,
              ...(ctx?.accessToken === undefined ? {} : { accessToken: ctx.accessToken }),
            },
            signer,
          ),
      }),
    );
    const proof = stub.callTo(CREDENTIAL_URL)?.headers.DPoP ?? '';
    expect(payloadOf(proof).ath).toBe(computeAth(ACCESS_TOKEN));
    // Token Request の proof は access_token が無い時点のもので、ath を持たない。
    expect(payloadOf(stub.callTo(TOKEN_URL)?.headers.DPoP ?? '').ath).toBeUndefined();
  });
});

describe('receiveCredential: JWT Proof の aud は Credential Issuer Identifier', () => {
  test('aud は credential_issuer で、Credential Endpoint の URL ではない', async () => {
    const stub = stubWith({ tokenResponse: tokenResponse() });
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    const claims = proofClaims(stub.callTo(CREDENTIAL_URL)?.body);
    expect(claims.aud).toBe(ISSUER);
    expect(claims.aud).not.toBe(CREDENTIAL_URL);
  });
});

describe('receiveCredential: JWT Proof の nonce の解決', () => {
  test('Token Response に c_nonce が無く nonce_endpoint がある → Nonce Endpoint の値が nonce になる', async () => {
    const stub = stubWith({
      nonceEndpoint: true,
      tokenResponse: () =>
        json({ access_token: ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600 }),
    });
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    expect(proofClaims(stub.callTo(CREDENTIAL_URL)?.body).nonce).toBe(NONCE_ENDPOINT_VALUE);
  });

  test('c_nonce も nonce_endpoint も無い → nonce の無い proof で Credential Request が送られる', async () => {
    const stub = stubWith({
      tokenResponse: () =>
        json({ access_token: ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600 }),
    });
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    const claims = proofClaims(stub.callTo(CREDENTIAL_URL)?.body);
    expect(Object.hasOwn(claims, 'nonce')).toBe(false);
    expect(claims.aud).toBe(ISSUER);
  });

  test('旧 Draft 形式（Token Response に c_nonce あり・nonce_endpoint なし）は従来どおり', async () => {
    const stub = stubWith({ tokenResponse: tokenResponse() });
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    expect(proofClaims(stub.callTo(CREDENTIAL_URL)?.body).nonce).toBe(C_NONCE);
  });

  test('c_nonce が空文字など不正な型なら Token Response ごと 8010 で拒否する', async () => {
    const stub = stubWith({
      tokenResponse: () =>
        json({ access_token: ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600, c_nonce: '' }),
    });
    await expect(
      receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub)),
    ).rejects.toMatchObject({
      code: '8010',
    });
    expect(stub.callTo(CREDENTIAL_URL)).toBeUndefined();
  });
});

describe('generateProofJWT: nonce は省略可能', () => {
  test('nonce 省略時は payload に nonce を載せず、空白のみの nonce は 3081 で拒否する', () => {
    const signer = createPrivateKeySigner(HOLDER_PRIVATE_KEY, 'ES256');
    const base = { audience: ISSUER, issuer: 'did:key:zHolder', keyId: 'did:key:zHolder#k' };
    const payload = payloadOf(generateProofJWT(base, signer));
    expect(Object.hasOwn(payload, 'nonce')).toBe(false);
    expect(payload.aud).toBe(ISSUER);
    expect(() => generateProofJWT({ ...base, nonce: '  ' }, signer)).toThrow(
      expect.objectContaining({ code: '3081' }),
    );
  });
});
