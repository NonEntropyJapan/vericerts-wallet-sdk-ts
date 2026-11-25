/**
 * OID4VP Authorization Request パース（URL クエリ / JAR）のユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - URL クエリ形式の必須パラメータ抽出と DCQL デコード。
 * - 必須欠落 / response_type 不正 / response_uri・client_id ドメイン不一致で 8030。
 * - `response_uri` が非 https なら、`client_id` と同一オリジンでも 8030。
 * - request_uri 参照は parseAuthorizationRequest では拒否（8030。判定規則は `oid4vp-request-query.test.ts`）。
 * - JAR JWT（実署名 JWS）からの Request 展開。
 * - `client_metadata`（`direct_post.jwt` の応答暗号化パラメータ）の展開。
 */

import { describe, expect, it } from 'bun:test';
import { createSdJwt } from '../../credential/sdjwt/sdjwt.js';
import { createPrivateKeySigner } from '../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { parseAuthorizationRequest, parseJarRequest } from '../request.js';

const CLIENT_ID = 'https://verifier.example.com';
const RESPONSE_URI = 'https://verifier.example.com/callback';
const NONCE = 'n-0S6_WzA2Mj-0123456789';
const STATE = 'af0ifjsldkj';

const DCQL = {
  credentials: [
    { id: 'pid', format: 'vc+sd-jwt', meta: { vct_values: ['https://example.com/pid'] } },
  ],
};

/** 正常系の URL クエリを組み立てる。 */
function buildUri(overrides: Record<string, string | undefined> = {}): string {
  const params: Record<string, string | undefined> = {
    response_type: 'vp_token',
    client_id: CLIENT_ID,
    response_mode: 'direct_post',
    response_uri: RESPONSE_URI,
    nonce: NONCE,
    state: STATE,
    dcql_query: JSON.stringify(DCQL),
    ...overrides,
  };
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      search.set(key, value);
    }
  }
  return `openid4vp://?${search.toString()}`;
}

describe('parseAuthorizationRequest（URL クエリ）', () => {
  it('必須パラメータを抽出し DCQL をデコードする', () => {
    const req = parseAuthorizationRequest(buildUri());
    expect(req.responseType).toBe('vp_token');
    expect(req.clientId).toBe(CLIENT_ID);
    expect(req.responseMode).toBe('direct_post');
    expect(req.responseUri).toBe(RESPONSE_URI);
    expect(req.nonce).toBe(NONCE);
    expect(req.state).toBe(STATE);
    expect(req.dcqlQuery?.credentials[0]?.id).toBe('pid');
    expect(req.dcqlQuery?.credentials[0]?.meta?.vct_values).toEqual(['https://example.com/pid']);
  });

  it('スキームなしの素のクエリ文字列も受理する', () => {
    const search = new URLSearchParams({
      response_type: 'vp_token',
      client_id: CLIENT_ID,
      response_mode: 'direct_post',
      response_uri: RESPONSE_URI,
      nonce: NONCE,
      state: STATE,
    });
    const req = parseAuthorizationRequest(search.toString());
    expect(req.clientId).toBe(CLIENT_ID);
    expect(req.dcqlQuery).toBeUndefined();
  });

  it('presentation_definition は生 JSON として保持する', () => {
    const pd = { id: 'pd-1', input_descriptors: [] };
    const req = parseAuthorizationRequest(
      buildUri({ dcql_query: undefined, presentation_definition: JSON.stringify(pd) }),
    );
    expect(req.presentationDefinition).toEqual(pd);
    expect(req.dcqlQuery).toBeUndefined();
  });

  it.each([
    'client_id',
    'response_uri',
    'nonce',
    'state',
    'response_mode',
  ] as const)('必須パラメータ %s 欠落で 8030', (key) => {
    try {
      parseAuthorizationRequest(buildUri({ [key]: undefined }));
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(VericertsError);
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('client_metadata を JSON object として展開する', () => {
    const metadata = {
      authorization_encrypted_response_alg: 'ECDH-ES',
      jwks: { keys: [{ kty: 'EC', crv: 'P-256', use: 'enc', x: 'eA', y: 'eQ' }] },
    };
    const req = parseAuthorizationRequest(
      buildUri({ response_mode: 'direct_post.jwt', client_metadata: JSON.stringify(metadata) }),
    );
    expect(req.responseMode).toBe('direct_post.jwt');
    expect(req.clientMetadata).toEqual(metadata);
  });

  it('client_metadata 未指定なら undefined のままにする', () => {
    expect(parseAuthorizationRequest(buildUri()).clientMetadata).toBeUndefined();
  });

  it('client_metadata が JSON object でない（配列）と 8030', () => {
    try {
      parseAuthorizationRequest(buildUri({ client_metadata: '[1,2]' }));
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('response_type が vp_token 以外で 8030', () => {
    try {
      parseAuthorizationRequest(buildUri({ response_type: 'id_token' }));
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('response_uri ドメインが client_id と不一致で 8030（フィッシング防止）', () => {
    try {
      parseAuthorizationRequest(
        buildUri({ response_uri: 'https://attacker.example.com/callback' }),
      );
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('response_uri が http なら client_id と同一オリジンでも 8030（平文送信の防止）', () => {
    try {
      parseAuthorizationRequest(
        buildUri({
          client_id: 'http://verifier.example.com',
          response_uri: 'http://verifier.example.com/callback',
        }),
      );
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
      expect((err as VericertsError).context).toEqual({ reason: 'insecure_response_uri' });
    }
  });

  it('nonce が 128-bit 未満（22 文字未満）なら 8030', () => {
    for (const nonce of ['n', 'abcd1234', 'a'.repeat(21)]) {
      try {
        parseAuthorizationRequest(buildUri({ nonce }));
        throw new Error('should have thrown');
      } catch (err) {
        expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
        expect((err as VericertsError).context).toEqual({ reason: 'nonce_too_short' });
      }
    }
    // 128-bit を base64url で表した最短の 22 文字は受理する。
    expect(parseAuthorizationRequest(buildUri({ nonce: 'a'.repeat(22) })).nonce).toBe(
      'a'.repeat(22),
    );
  });

  it('dcql_query が不正 JSON で 8030', () => {
    try {
      parseAuthorizationRequest(buildUri({ dcql_query: '{not json' }));
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  // 参照形式は未対応ではない。取得・解析は 2 API が担い、回帰は `jar/__tests__/` が固定する。
  it('request_uri 参照のみのリクエストは同期 API では 8030（parsePresentationRequest を使う）', () => {
    try {
      parseAuthorizationRequest(
        'openid4vp://?request_uri=https://verifier.example.com/request/123',
      );
      throw new Error('should have thrown');
    } catch (err) {
      const error = err as VericertsError;
      expect(error.code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
      expect(error.context).toMatchObject({ reason: 'request_uri_reference' });
    }
  });

  it('空クエリで 8030', () => {
    try {
      parseAuthorizationRequest('openid4vp://?');
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });
});

describe('parseJarRequest（JAR JWT）', () => {
  const JAR_KEY = new Uint8Array(32).fill(7);
  const signer = createPrivateKeySigner(JAR_KEY, 'ES256');

  /** OID4VP パラメータを payload に持つ JAR JWT（コンパクト JWS）を実署名で作る。 */
  function buildJarJwt(payload: Record<string, unknown>): string {
    // createSdJwt の Issuer-signed JWT 部分（最初の ~ より前）を JWS として流用する。
    const sdJwt = createSdJwt(signer, {
      vct: 'jar',
      disclosureClaims: [],
      claims: payload,
    });
    return sdJwt.split('~')[0] as string;
  }

  it('JAR payload から Request を展開し DCQL をパースする', () => {
    const jwt = buildJarJwt({
      response_type: 'vp_token',
      client_id: CLIENT_ID,
      response_mode: 'direct_post',
      response_uri: RESPONSE_URI,
      nonce: NONCE,
      state: STATE,
      dcql_query: DCQL,
    });
    const req = parseJarRequest(jwt);
    expect(req.clientId).toBe(CLIENT_ID);
    expect(req.dcqlQuery?.credentials[0]?.id).toBe('pid');
  });

  it('JAR payload の client_metadata を展開する', () => {
    const metadata = {
      authorization_encrypted_response_alg: 'ECDH-ES',
      jwks: { keys: [{ kty: 'EC', crv: 'P-256', use: 'enc', x: 'eA', y: 'eQ' }] },
    };
    const jwt = buildJarJwt({
      response_type: 'vp_token',
      client_id: CLIENT_ID,
      response_mode: 'direct_post.jwt',
      response_uri: RESPONSE_URI,
      nonce: NONCE,
      state: STATE,
      client_metadata: metadata,
    });
    expect(parseJarRequest(jwt).clientMetadata).toEqual(metadata);
  });

  it('JAR の response_uri が http なら 8030（URL クエリ経路と同じ検査を通す）', () => {
    const jwt = buildJarJwt({
      response_type: 'vp_token',
      client_id: 'http://verifier.example.com',
      response_mode: 'direct_post',
      response_uri: 'http://verifier.example.com/callback',
      nonce: NONCE,
      state: STATE,
    });
    expect(() => parseJarRequest(jwt)).toThrow(
      new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED),
    );
  });

  it('JAR の client_metadata が object でないと 8030', () => {
    const jwt = buildJarJwt({
      response_type: 'vp_token',
      client_id: CLIENT_ID,
      response_mode: 'direct_post.jwt',
      response_uri: RESPONSE_URI,
      nonce: NONCE,
      state: STATE,
      client_metadata: 'not-an-object',
    });
    try {
      parseJarRequest(jwt);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('必須パラメータ欠落の JAR で 8030', () => {
    const jwt = buildJarJwt({
      response_type: 'vp_token',
      client_id: CLIENT_ID,
      response_mode: 'direct_post',
      // response_uri 欠落
      nonce: NONCE,
      state: STATE,
    });
    try {
      parseJarRequest(jwt);
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });

  it('JWS 形式不正の JAR で 8030', () => {
    try {
      parseJarRequest('not-a-jwt');
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as VericertsError).code).toBe(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
    }
  });
});
