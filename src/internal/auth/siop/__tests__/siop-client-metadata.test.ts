/**
 * DIDベース SIOPv2 の標準どおりの RP リクエスト。
 *
 * vericerts-anchorは `registration` を送らず、`client_metadata` に標準の `id_token_signed_response_alg`（単一の文字列）
 * だけを載せ（`id_token_signing_alg_values_supported` は無い）、`response_type=id_token` で要求する。
 * 以前の SDK は複数形の配列を必須としていたため、この形の `client_metadata` を捨てて 4002 で拒否していた。
 * `client_metadata_uri`（メタデータ文書の URL）も同じ検査で受け付ける。
 */

import { describe, expect, test } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { parseSIOPv2Request } from '../parse.js';
import { processSIOPv2Request } from '../process.js';
import { anchorRequest, decodeJwt, HOLDER_DID, NOW } from './siop-login.fixtures.js';

const METADATA_URI = 'https://anchor.example.com/v1/login/client-metadata.json';

const es256k = createPrivateKeySigner(new Uint8Array(32).fill(21), 'ES256K');
const es256 = createPrivateKeySigner(new Uint8Array(32).fill(22), 'ES256');

/** vericerts-anchor が送る形（`response_type=id_token`、`client_metadata` は `id_token_signed_response_alg` だけ）。 */
function standardRequest(metadata: Record<string, unknown> | null = {}): Record<string, unknown> {
  return anchorRequest({
    response_type: 'id_token',
    client_metadata:
      metadata === null
        ? undefined
        : {
            subject_syntax_types_supported: ['did:key', 'did:web', 'did:jwk'],
            id_token_signed_response_alg: 'ES256K',
            ...metadata,
          },
  });
}

/** 取得先の応答を固定する fetch スタブ。呼ばれた URL を `calls` に残す。 */
function stubFetch(
  body: unknown,
  init: { status?: number; contentType?: string } = {},
): { fetchImpl: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (input) => {
    calls.push(input);
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status: init.status ?? 200,
      headers: { 'content-type': init.contentType ?? 'application/json' },
    });
  };
  return { fetchImpl, calls };
}

describe('client_metadata の id_token_signed_response_alg（標準）', () => {
  test('client_metadata だけ・id_token_signed_response_alg だけの標準の要求が ES256K の鍵で通る', async () => {
    const response = await processSIOPv2Request(standardRequest(), HOLDER_DID, es256k, {
      nowSeconds: NOW,
    });
    expect(response.vpToken).toBeUndefined();
    expect(decodeJwt(response.idToken).header.alg).toBe('ES256K');
  });

  test('parse は id_token_signed_response_alg を clientMetadata へ展開する', () => {
    expect(parseSIOPv2Request(standardRequest()).clientMetadata).toEqual({
      subjectSyntaxTypesSupported: ['did:key', 'did:web', 'did:jwk'],
      idTokenSignedResponseAlg: 'ES256K',
    });
  });

  test('siopv2:// URI のクエリ（client_metadata は JSON 文字列）でも通る', async () => {
    const request = standardRequest();
    const query = new URLSearchParams({
      ...(request as Record<string, string>),
      client_metadata: JSON.stringify(request.client_metadata),
    });
    const response = await processSIOPv2Request(`siopv2://?${query}`, HOLDER_DID, es256k, {
      nowSeconds: NOW,
    });
    expect(response.idToken.split('.')).toHaveLength(3);
  });

  test('signer の alg が id_token_signed_response_alg と違えば 4002（ES256 の鍵では ES256K を求める RP にログインできない）', async () => {
    await expect(
      processSIOPv2Request(standardRequest(), HOLDER_DID, es256, { nowSeconds: NOW }),
    ).rejects.toMatchObject({
      code: ErrorCodes.RP_REGISTRATION_INVALID,
      context: { reason: 'signing_alg_unsupported' },
    });
  });

  test('複数形と単一の両方を宣言していれば、両方を満たす必要がある', async () => {
    const request = standardRequest({ id_token_signing_alg_values_supported: ['ES256'] });
    await expect(
      processSIOPv2Request(request, HOLDER_DID, es256k, { nowSeconds: NOW }),
    ).rejects.toMatchObject({ code: ErrorCodes.RP_REGISTRATION_INVALID });
    const both = standardRequest({ id_token_signing_alg_values_supported: ['ES256', 'ES256K'] });
    const response = await processSIOPv2Request(both, HOLDER_DID, es256k, { nowSeconds: NOW });
    expect(response.idToken.split('.')).toHaveLength(3);
  });

  test('署名アルゴリズムをどちらも宣言しない client_metadata は 4002（検証できないので送らない）', async () => {
    await expect(
      processSIOPv2Request(
        standardRequest({ id_token_signed_response_alg: undefined }),
        HOLDER_DID,
        es256k,
        { nowSeconds: NOW },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.RP_REGISTRATION_INVALID });
  });

  test('vp_token を要求するのに id_token_signed_response_alg が文字列でなければ 4001', () => {
    expect(() =>
      parseSIOPv2Request(
        anchorRequest({
          client_metadata: {
            subject_syntax_types_supported: ['did:key'],
            id_token_signed_response_alg: ['ES256K'],
          },
        }),
      ),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED }));
  });
});

describe('client_metadata_uri', () => {
  const uriRequest = (overrides: Record<string, unknown> = {}) => ({
    ...standardRequest(null),
    client_metadata_uri: METADATA_URI,
    ...overrides,
  });
  const document = {
    subject_syntax_types_supported: ['did:key'],
    id_token_signed_response_alg: 'ES256K',
  };

  test('parse は clientMetadataUri を読むだけで、取得しない', () => {
    const request = parseSIOPv2Request(uriRequest());
    expect(request.clientMetadataUri).toBe(METADATA_URI);
    expect(request.clientMetadata).toBeUndefined();
  });

  test('承認後の processSIOPv2Request が文書を取得し、標準の client_metadata と同じ検査で通る', async () => {
    const { fetchImpl, calls } = stubFetch(document);
    const response = await processSIOPv2Request(uriRequest(), HOLDER_DID, es256k, {
      nowSeconds: NOW,
      fetchImpl,
    });
    expect(calls).toEqual([METADATA_URI]);
    expect(decodeJwt(response.idToken).header.alg).toBe('ES256K');
  });

  test('siopv2:// URI のクエリの client_metadata_uri でも取得して通る', async () => {
    const { fetchImpl, calls } = stubFetch(document);
    const query = new URLSearchParams(uriRequest() as Record<string, string>);
    await processSIOPv2Request(`siopv2://?${query}`, HOLDER_DID, es256k, {
      nowSeconds: NOW,
      fetchImpl,
    });
    expect(calls).toEqual([METADATA_URI]);
  });

  test('取得した文書の alg が signer と違えば 4002', async () => {
    const { fetchImpl } = stubFetch({ ...document, id_token_signed_response_alg: 'ES256' });
    await expect(
      processSIOPv2Request(uriRequest(), HOLDER_DID, es256k, { nowSeconds: NOW, fetchImpl }),
    ).rejects.toMatchObject({
      code: ErrorCodes.RP_REGISTRATION_INVALID,
      context: { reason: 'signing_alg_unsupported' },
    });
  });

  test('取得した文書の形が不正なら 4001', async () => {
    const { fetchImpl } = stubFetch({ subject_syntax_types_supported: 'did:key' });
    await expect(
      processSIOPv2Request(uriRequest(), HOLDER_DID, es256k, { nowSeconds: NOW, fetchImpl }),
    ).rejects.toMatchObject({ code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED });
  });

  test.each([
    ['HTTP エラー', { status: 500 }, 'client_metadata_uri_http_error'],
    [
      'Content-Type が JSON でない',
      { contentType: 'text/html' },
      'client_metadata_uri_invalid_content_type',
    ],
  ])('取得に失敗する（%s）と 4002（URL・本文は context に載せない）', async (_name, init, reason) => {
    const { fetchImpl } = stubFetch(document, init);
    await expect(
      processSIOPv2Request(uriRequest(), HOLDER_DID, es256k, { nowSeconds: NOW, fetchImpl }),
    ).rejects.toMatchObject({ code: ErrorCodes.RP_REGISTRATION_INVALID, context: { reason } });
  });

  test('client_metadata_uri が公開 HTTPS でなければ、取得せず 4001', async () => {
    for (const uri of ['http://anchor.example.com/m.json', 'https://10.0.0.5/m.json']) {
      const { fetchImpl, calls } = stubFetch(document);
      await expect(
        processSIOPv2Request(uriRequest({ client_metadata_uri: uri }), HOLDER_DID, es256k, {
          nowSeconds: NOW,
          fetchImpl,
        }),
      ).rejects.toMatchObject({ code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED });
      expect(calls).toEqual([]);
    }
  });

  test('client_metadata と client_metadata_uri の併記は 4001（出所が 2 つあると曖昧）', async () => {
    const { fetchImpl, calls } = stubFetch(document);
    await expect(
      processSIOPv2Request(
        { ...standardRequest(), client_metadata_uri: METADATA_URI },
        HOLDER_DID,
        es256k,
        { nowSeconds: NOW, fetchImpl },
      ),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED,
      context: { reason: 'client_metadata_uri_conflict' },
    });
    expect(calls).toEqual([]);
  });
});
