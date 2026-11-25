/**
 * `receivePIDCredential` のテスト。
 *
 * 受領の正常系と、Offer / 通信 / 応答 / Rulebook のそれぞれで fail-closed に落ちることを検証する。
 * ネットワークは `fetchImpl` 注入のみで再現し、グローバル `fetch` は差し替えない。
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../../errors.js';
import { PID_VCT } from '../../../../eudi/pid/index.js';
import { receivePIDCredential } from '../receive.js';
import {
  AS_C_NONCE,
  AS_METADATA_URL,
  asMetadataResponse,
  buildOfferURI,
  buildSdJwtVc,
  CREDENTIAL_URL,
  createIssuerStub,
  createStubFetch,
  credentialResponse,
  defaultOfferURI,
  ISSUER,
  jsonResponse,
  METADATA_URL,
  NONCE_URL,
  nonceResponse,
  receiveDeps,
  TOKEN_URL,
  tokenResponse,
  VALID_PID_CLAIMS,
} from './issuance-fixtures.js';

/** ARF PID Rulebook を満たす PID の SD-JWT VC。 */
function validPidSdJwt(): string {
  return buildSdJwtVc({ claims: VALID_PID_CLAIMS });
}

describe('receivePIDCredential', () => {
  test('正常系: claims と raw を持つ PID を返す', async () => {
    const sdJwt = validPidSdJwt();
    const stub = createIssuerStub(sdJwt);
    const pid = await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
    expect(pid.vct).toBe(PID_VCT);
    expect(pid.raw).toBe(sdJwt);
    expect(pid.claims.family_name).toBe('Bianchi');
    expect(pid.claims.issuing_country).toBe('IT');
    // 構造クレーム（vct / iss / iat）は属性集合から除かれる。
    expect(Object.hasOwn(pid.claims, 'vct')).toBe(false);
    expect(Object.hasOwn(pid.claims, 'iss')).toBe(false);
    // Issuer Metadata → AS Metadata（Token Endpoint の解決）→ Token → Credential の順に通信する。
    expect(stub.calls.map((call) => call.url)).toEqual([
      METADATA_URL,
      AS_METADATA_URL,
      TOKEN_URL,
      CREDENTIAL_URL,
    ]);
  });

  test('Credential Request は dc+sd-jwt と JWT Proof を送る', async () => {
    const stub = createIssuerStub(validPidSdJwt());
    await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
    const credentialCall = stub.calls.find((call) => call.url === CREDENTIAL_URL);
    const body = JSON.parse(credentialCall?.body ?? '{}') as Record<string, unknown>;
    expect(body.format).toBe('dc+sd-jwt');
    // SD-JWT VC は型を `vct` で伝える（旧 Draft 形。draft-13 Annex A.3。1.0 Final の要求に `vct` は無い）。
    expect(body.vct).toBe(PID_VCT);
    expect(body).not.toHaveProperty('credential_definition');
    const proof = body.proof as { proof_type: string; jwt: string };
    expect(proof.proof_type).toBe('jwt');
    // JWT Proof は c_nonce にバインドされ、Credential Issuer Identifier を aud とする（OID4VCI 1.0 §8.2.1.1）。
    const payload = JSON.parse(
      new TextDecoder().decode(Buffer.from(proof.jwt.split('.')[1] ?? '', 'base64url')),
    ) as Record<string, unknown>;
    expect(payload.nonce).toBe('c-nonce-xyz');
    expect(payload.aud).toBe(ISSUER);
    expect(payload.aud).not.toBe(CREDENTIAL_URL);
    expect(payload.iss).toBe('did:key:zHolder');
  });

  test('Issuer が vct を告知していれば、PID の固定 vct ではなく告知値を送る', async () => {
    // `resolveCredentialVct(offer, endpoints) ?? selectVct(offer)` の優先順位。告知値が固定値に負けると、
    // `vct` を告知値と突き合わせる Issuer（walt.id 等）に発行セッションを紐づけられず HTTP 400 になる。
    const advertised = 'https://issuer.example.eu/credentials/pid';
    const stub = createStubFetch({
      [METADATA_URL]: () =>
        jsonResponse({
          credential_issuer: ISSUER,
          credential_endpoint: CREDENTIAL_URL,
          token_endpoint: TOKEN_URL,
          credential_configurations_supported: {
            [PID_VCT]: { format: 'dc+sd-jwt', vct: advertised },
          },
        }),
      [AS_METADATA_URL]: () => asMetadataResponse(),
      [TOKEN_URL]: tokenResponse,
      [CREDENTIAL_URL]: () => credentialResponse(validPidSdJwt()),
    });
    await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
    const credentialCall = stub.calls.find((call) => call.url === CREDENTIAL_URL);
    const body = JSON.parse(credentialCall?.body ?? '{}') as Record<string, unknown>;
    expect(body.vct).toBe(advertised);
    expect(body.vct).not.toBe(PID_VCT);
    expect(body).not.toHaveProperty('credential_definition');
  });

  test('必須属性の欠落は 10002', async () => {
    const claims = { ...VALID_PID_CLAIMS };
    delete (claims as Record<string, unknown>).issuing_authority;
    const stub = createIssuerStub(buildSdJwtVc({ claims }));
    try {
      await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10002');
    }
  });

  test('任意属性の型違反は 10001', async () => {
    const stub = createIssuerStub(
      buildSdJwtVc({ claims: { ...VALID_PID_CLAIMS, age_over_18: 'yes' } }),
    );
    try {
      await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10001');
    }
  });

  test('vct が PID でない VC を受領したら 10001', async () => {
    const stub = createIssuerStub(
      buildSdJwtVc({ vct: 'urn:eudi:eaa:other:1', claims: VALID_PID_CLAIMS }),
    );
    try {
      await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10001');
    }
  });

  test('pre-authorized_code grant が無い Offer は 3003（通信は発生しない）', async () => {
    const stub = createIssuerStub(validPidSdJwt());
    const offerURI = buildOfferURI({
      credential_issuer: ISSUER,
      credential_configuration_ids: [PID_VCT],
    });
    try {
      await receivePIDCredential(offerURI, receiveDeps(stub.fetchImpl));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('3003');
    }
    expect(stub.calls).toHaveLength(0);
  });

  test('deferred 応答は 8020', async () => {
    const stub = createStubFetch({
      [METADATA_URL]: () =>
        jsonResponse({
          credential_issuer: ISSUER,
          credential_endpoint: CREDENTIAL_URL,
          token_endpoint: TOKEN_URL,
        }),
      [TOKEN_URL]: tokenResponse,
      [CREDENTIAL_URL]: () => jsonResponse({ transaction_id: 'tx-1' }),
    });
    try {
      await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8020');
    }
  });

  test('SD-JWT として解釈できない VC は 8020', async () => {
    const stub = createIssuerStub('not-an-sd-jwt');
    try {
      await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8020');
    }
  });

  test('signer / keyId を欠く deps は 8020（通信は発生しない）', async () => {
    const stub = createIssuerStub(validPidSdJwt());
    const deps = { ...receiveDeps(stub.fetchImpl), keyId: '  ' };
    try {
      await receivePIDCredential(defaultOfferURI(), deps);
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('8020');
    }
    expect(stub.calls).toHaveLength(0);
  });
});

describe('receivePIDCredential: OID4VCI 1.0 Final 形式の Issuer', () => {
  /** Issuer Metadata に token_endpoint が無く、Token Response に c_nonce が無い Final 準拠の Issuer。 */
  function finalIssuerStub(nonceEndpoint: boolean): ReturnType<typeof createStubFetch> {
    return createStubFetch({
      [METADATA_URL]: () =>
        jsonResponse({
          credential_issuer: ISSUER,
          credential_endpoint: CREDENTIAL_URL,
          ...(nonceEndpoint ? { nonce_endpoint: NONCE_URL } : {}),
        }),
      [AS_METADATA_URL]: () => asMetadataResponse(),
      [NONCE_URL]: nonceResponse,
      [TOKEN_URL]: () =>
        jsonResponse({ access_token: 'at', token_type: 'Bearer', expires_in: 3600 }),
      [CREDENTIAL_URL]: () => credentialResponse(validPidSdJwt()),
    });
  }

  function proofPayload(stub: ReturnType<typeof createStubFetch>): Record<string, unknown> {
    const body = JSON.parse(stub.calls.find((c) => c.url === CREDENTIAL_URL)?.body ?? '{}') as {
      proof: { jwt: string };
    };
    return JSON.parse(
      new TextDecoder().decode(Buffer.from(body.proof.jwt.split('.')[1] ?? '', 'base64url')),
    ) as Record<string, unknown>;
  }

  test('Nonce Endpoint の値が proof の nonce になり、Token Endpoint は AS Metadata から引く', async () => {
    const stub = finalIssuerStub(true);
    await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
    expect(proofPayload(stub).nonce).toBe(AS_C_NONCE);
    expect(stub.calls.some((c) => c.url === TOKEN_URL)).toBe(true);
  });

  test('nonce_endpoint も c_nonce も無い Issuer には nonce の無い proof を送る', async () => {
    const stub = finalIssuerStub(false);
    await receivePIDCredential(defaultOfferURI(), receiveDeps(stub.fetchImpl));
    expect(Object.hasOwn(proofPayload(stub), 'nonce')).toBe(false);
  });
});
