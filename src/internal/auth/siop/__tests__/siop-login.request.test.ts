/**
 * DIDベース SIOPv2 `vp_token id_token` ログインの要求側（パース・RP メタデータ・`processSIOPv2Request` のエラー 4001 / 4002）を検証する。
 * トークンの中身は `siop-login.test.ts`。
 */

import { describe, expect, test } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes } from '../../../errors.js';
import { parseSIOPv2Request } from '../parse.js';
import { processSIOPv2Request } from '../process.js';
import { assertValidRPRegistration } from '../rp-registration.js';
import { anchorRequest, CLIENT_ID, HOLDER_DID, NOW } from './siop-login.fixtures.js';

describe('anchor の JSON 要求のパース', () => {
  test('state・response_mode・id_token_type・client_metadata を読む', () => {
    expect(parseSIOPv2Request(anchorRequest())).toMatchObject({
      responseType: 'vp_token id_token',
      state: 'state-0123456789AbCdEf',
      responseMode: 'direct_post',
      idTokenType: 'subject_signed_id_token',
      clientMetadata: {
        subjectSyntaxTypesSupported: ['did:key', 'did:web', 'did:jwk'],
        idTokenSigningAlgValuesSupported: ['ES256', 'ES256K'],
        jwtVpAlgValuesSupported: ['ES256', 'ES256K'],
      },
    });
  });

  test('siopv2:// URI のクエリでも state と client_metadata（JSON 文字列）を読む', () => {
    const request = anchorRequest();
    const query = new URLSearchParams({
      ...(request as Record<string, string>),
      client_metadata: JSON.stringify(request.client_metadata),
    });
    expect(parseSIOPv2Request(`siopv2://?${query}`)).toMatchObject({
      state: 'state-0123456789AbCdEf',
      clientMetadata: { idTokenSigningAlgValuesSupported: ['ES256', 'ES256K'] },
    });
  });

  test.each([
    [
      'client_metadata の形が不正',
      { client_metadata: { subject_syntax_types_supported: 'did:key' } },
    ],
    [
      'vp_formats_supported.jwt_vp.alg_values の形が不正',
      {
        client_metadata: {
          subject_syntax_types_supported: ['did:key'],
          id_token_signing_alg_values_supported: ['ES256'],
          vp_formats_supported: { jwt_vp: { alg_values: 'ES256' } },
        },
      },
    ],
  ])('vp_token を要求するのに %s と 4001（検証できないメタデータで署名しない）', (_name, overrides) => {
    expect(() => parseSIOPv2Request(anchorRequest(overrides))).toThrow(
      expect.objectContaining({ code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED }),
    );
  });

  // 回帰: `eudi_authenticatePseudonym` と承認前の宛先解析は `parseSIOPv2Request` だけを呼ぶ。
  // vp_token 固有の検査や他形式のメタデータで、これまで通っていた要求を落とさない。
  describe('parse は旧来の要求を落とさない', () => {
    test('vp_token を含まない要求の、他形式の client_metadata は無視して通る（registration へ倒れる）', () => {
      const request = parseSIOPv2Request(
        anchorRequest({
          response_type: 'id_token',
          client_metadata: { vp_formats_supported: { jwt_vp: {} } },
        }),
      );
      expect(request.clientMetadata).toBeUndefined();
    });

    test('旧来の registration に形の悪い vp_formats_supported があっても、vp_token を含まない要求の parse は通る', () => {
      const request = parseSIOPv2Request(
        anchorRequest({
          response_type: 'id_token',
          client_metadata: undefined,
          registration: {
            subject_syntax_types_supported: ['did:key'],
            id_token_signing_alg_values_supported: ['ES256'],
            vp_formats_supported: [],
          },
        }),
      );
      expect(request.registration?.jwtVpAlgValuesSupported).toBeUndefined();
    });

    test('state が無い vp_token 要求も parse は通る（state の必須検査は processSIOPv2Request）', () => {
      expect(parseSIOPv2Request(anchorRequest({ state: undefined })).state).toBeUndefined();
    });

    test('siopv2:// URI に空の state= / response_mode= / id_token_type= が付いていても通る', () => {
      const uri = `siopv2://?${new URLSearchParams({
        scope: 'openid',
        response_type: 'id_token',
        client_id: CLIENT_ID,
        redirect_uri: CLIENT_ID,
        nonce: 'n',
        state: '',
        response_mode: '',
        id_token_type: '',
      })}`;
      expect(parseSIOPv2Request(uri)).toMatchObject({
        state: undefined,
        responseMode: undefined,
        idTokenType: undefined,
      });
    });
  });

  test('JSON オブジェクトでない入力は 4001', () => {
    expect(() => parseSIOPv2Request(null as never)).toThrow(
      expect.objectContaining({ code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED }),
    );
    expect(() => parseSIOPv2Request([] as never)).toThrow(
      expect.objectContaining({ code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED }),
    );
  });
});

describe('RP メタデータの検証（client_metadata 標準・registration 後方互換）', () => {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');

  test('client_metadata があれば registration より優先する', () => {
    const request = parseSIOPv2Request(
      anchorRequest({
        registration: {
          subject_syntax_types_supported: ['did'],
          id_token_signing_alg_values_supported: ['EdDSA'],
        },
      }),
    );
    expect(assertValidRPRegistration(request, 'ES256').idTokenSigningAlgValuesSupported).toEqual([
      'ES256',
      'ES256K',
    ]);
  });

  test('client_metadata が無ければ registration を使う（後方互換）', async () => {
    const response = await processSIOPv2Request(
      anchorRequest({
        client_metadata: undefined,
        registration: {
          subject_syntax_types_supported: ['did:key'],
          id_token_signing_alg_values_supported: ['ES256'],
        },
      }),
      HOLDER_DID,
      signer,
      { nowSeconds: NOW },
    );
    expect(response.vpToken).toBeDefined();
  });

  test('client_metadata も registration も無ければ 4002', async () => {
    await expect(
      processSIOPv2Request(anchorRequest({ client_metadata: undefined }), HOLDER_DID, signer, {
        nowSeconds: NOW,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.RP_REGISTRATION_INVALID });
  });

  test('RP が受理する署名アルゴリズムに signer の alg が無ければ 4002（Ed25519 の鍵ではログインできない）', async () => {
    const edSigner = createPrivateKeySigner(new Uint8Array(32).fill(13), 'EdDSA');
    await expect(
      processSIOPv2Request(anchorRequest(), HOLDER_DID, edSigner, { nowSeconds: NOW }),
    ).rejects.toMatchObject({ code: ErrorCodes.RP_REGISTRATION_INVALID });
  });

  test('jwt_vp.alg_values が signer の alg を含まなければ 4002（VP を RP が受理しない署名で作らない）', async () => {
    await expect(
      processSIOPv2Request(
        anchorRequest({
          client_metadata: {
            subject_syntax_types_supported: ['did:key'],
            id_token_signing_alg_values_supported: ['ES256'],
            vp_formats_supported: { jwt_vp: { alg_values: ['ES256K'] } },
          },
        }),
        HOLDER_DID,
        signer,
        { nowSeconds: NOW },
      ),
    ).rejects.toMatchObject({ code: ErrorCodes.RP_REGISTRATION_INVALID });
  });
});

describe('vp_token を要求する要求を Wallet が返せるか（processSIOPv2Request の 4001）', () => {
  const signer = createPrivateKeySigner(new Uint8Array(32).fill(11), 'ES256');

  test.each([
    ['state が無い', { state: undefined }],
    ['state が空', { state: '' }],
    ['response_mode が direct_post でない', { response_mode: 'fragment' }],
    [
      'response_mode が無い（OID4VP の既定は fragment なので明示を求める）',
      { response_mode: undefined },
    ],
    [
      'id_token_type が subject_signed_id_token を含まない',
      { id_token_type: 'attester_signed_id_token' },
    ],
    // VC を求める要求に VC なしの VP を返すと、RP に黙って別物を渡す。評価できないので拒否する。
    ['dcql_query を含む', { dcql_query: { credentials: [{ id: 'c', format: 'jwt_vc_json' }] } }],
    [
      'presentation_definition を含む',
      { presentation_definition: { id: 'pd', input_descriptors: [] } },
    ],
    [
      'presentation_definition_uri を含む',
      { presentation_definition_uri: 'https://rp.example.com/pd' },
    ],
    ['claims を含む', { claims: { vp_token: { presentation_definition: {} } } }],
  ])('%s と 4001 で、署名しない', async (_name, overrides) => {
    await expect(
      processSIOPv2Request(anchorRequest(overrides), HOLDER_DID, signer, { nowSeconds: NOW }),
    ).rejects.toMatchObject({ code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED });
  });

  test('VC を求める問い合わせが null / 空文字なら、載っていないものとして通る', async () => {
    const response = await processSIOPv2Request(
      anchorRequest({ dcql_query: null, presentation_definition: '' }),
      HOLDER_DID,
      signer,
      { nowSeconds: NOW },
    );
    expect(response.vpToken).toBeDefined();
  });

  test('id_token だけの旧来の要求は、claims を含んでいても拒否しない（vp_token を返さないため）', async () => {
    const response = await processSIOPv2Request(
      anchorRequest({ response_type: 'id_token', claims: { id_token: {} } }),
      HOLDER_DID,
      signer,
      { nowSeconds: NOW },
    );
    expect(response.vpToken).toBeUndefined();
  });

  test('id_token_type を省略した要求は通る', async () => {
    const response = await processSIOPv2Request(
      anchorRequest({ id_token_type: undefined }),
      HOLDER_DID,
      signer,
      { nowSeconds: NOW },
    );
    expect(response.vpToken).toBeDefined();
  });
});
