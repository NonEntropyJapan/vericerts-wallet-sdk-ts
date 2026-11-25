/**
 * OID4VCI Credential Endpoint 呼び出し（`requestCredential`）のユニットテスト。
 *
 * fetch を注入してリクエスト組み立てとレスポンス処理を検証する:
 * - 即時発行: `credential` を返す → status 'issued'。
 * - 遅延発行: `transaction_id` を返す → status 'deferred'。
 * - リクエスト: Authorization Bearer / body の format・credential_definition・proof。
 * - HTTP エラー → CREDENTIAL_REQUEST_FAILED (8020)。
 * - ネットワークエラー → ISSUER_COMMUNICATION_FAILED (3004)。
 * - JSON 不正 / credential も transaction_id も無い → CREDENTIAL_REQUEST_FAILED (8020)。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  type CredentialDefinition,
  type FetchLike,
  requestCredential,
} from '../../oid4vci/oid4vci.js';

const ENDPOINT = 'https://issuer.example.com/credential';
const ACCESS_TOKEN = 'access-token-xyz';
const FORMAT = 'jwt_vc_json';
const DEFINITION: CredentialDefinition = {
  type: ['VerifiableCredential', 'UniversityDegree'],
};
const PROOF_JWT = 'eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJ9.sig';
const VC_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.vc-sig';

/** Response を組み立てるヘルパ。 */
function jsonResponse(body: unknown, init?: { status?: number }): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** 共通オプションに fetch を差し込む。 */
function opts(fetchImpl: FetchLike) {
  return {
    credentialEndpoint: ENDPOINT,
    accessToken: ACCESS_TOKEN,
    format: FORMAT,
    credentialDefinition: DEFINITION,
    proofJwt: PROOF_JWT,
    fetchImpl,
  };
}

describe('requestCredential', () => {
  it('即時発行 VC を status=issued で返す', async () => {
    const fetchImpl: FetchLike = async () =>
      jsonResponse({ credential: VC_JWT, c_nonce: 'next-nonce' });
    const result = await requestCredential(opts(fetchImpl));
    expect(result.status).toBe('issued');
    if (result.status === 'issued') {
      expect(result.credential).toBe(VC_JWT);
      expect(result.cNonce).toBe('next-nonce');
    }
  });

  it('遅延発行を status=deferred で返す', async () => {
    const fetchImpl: FetchLike = async () =>
      jsonResponse({ transaction_id: 'tx-123', c_nonce: 'next-nonce' });
    const result = await requestCredential(opts(fetchImpl));
    expect(result.status).toBe('deferred');
    if (result.status === 'deferred') {
      expect(result.transactionId).toBe('tx-123');
      expect(result.cNonce).toBe('next-nonce');
    }
  });

  it('Authorization Bearer と body（format/definition/proof）を組み立てる', async () => {
    let capturedUrl: string | undefined;
    let capturedInit: Parameters<FetchLike>[1] | undefined;
    const fetchImpl: FetchLike = async (url, init) => {
      capturedUrl = url;
      capturedInit = init;
      return jsonResponse({ credential: VC_JWT });
    };
    await requestCredential(opts(fetchImpl));

    expect(capturedUrl).toBe(ENDPOINT);
    expect(capturedInit?.method).toBe('POST');
    const headers = capturedInit?.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(headers['Content-Type']).toBe('application/json');

    const body = JSON.parse(capturedInit?.body as string);
    expect(body.format).toBe(FORMAT);
    expect(body.credential_definition).toEqual(DEFINITION);
    expect(body.proof).toEqual({ proof_type: 'jwt', jwt: PROOF_JWT });
  });

  it('HTTP エラーは CREDENTIAL_REQUEST_FAILED (8020)', async () => {
    const fetchImpl: FetchLike = async () =>
      jsonResponse({ error: 'invalid_proof' }, { status: 400 });
    await expect(requestCredential(opts(fetchImpl))).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
    });
  });

  it('ネットワークエラーは ISSUER_COMMUNICATION_FAILED (3004)', async () => {
    const fetchImpl: FetchLike = async () => {
      throw new Error('network down');
    };
    try {
      await requestCredential(opts(fetchImpl));
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.ISSUER_COMMUNICATION_FAILED);
    }
  });

  it('JSON 不正は CREDENTIAL_REQUEST_FAILED (8020)', async () => {
    const fetchImpl: FetchLike = async () =>
      new Response('not-json', { status: 200, headers: { 'Content-Type': 'application/json' } });
    await expect(requestCredential(opts(fetchImpl))).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
    });
  });

  it('credential も transaction_id も無い応答は CREDENTIAL_REQUEST_FAILED (8020)', async () => {
    const fetchImpl: FetchLike = async () => jsonResponse({ c_nonce: 'only-nonce' });
    await expect(requestCredential(opts(fetchImpl))).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
    });
  });

  it.each([
    'http://issuer.example.com/credential',
    'not-a-url',
  ])('HTTPS 以外 / 不正 URL のエンドポイント（%s）は fetch せず CREDENTIAL_REQUEST_FAILED (8020)', async (endpoint) => {
    let called = false;
    const fetchImpl: FetchLike = async () => {
      called = true;
      return jsonResponse({ credential: VC_JWT });
    };
    await expect(
      requestCredential({ ...opts(fetchImpl), credentialEndpoint: endpoint }),
    ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    // access_token を平文送信しないため fetch は呼ばれない。
    expect(called).toBe(false);
  });
});
