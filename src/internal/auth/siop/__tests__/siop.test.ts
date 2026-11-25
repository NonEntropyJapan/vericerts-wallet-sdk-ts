/**
 * DIDベース SIOPv2 の統合テスト。
 *
 * 検証観点:
 * - `parseSIOPv2Request` が必須パラメータを検証し、正常系を正しく展開する。
 * - 必須パラメータ欠落・`redirect_uri` の非 HTTPS・`registration` の JSON 構文不正はいずれも
 *   `4001 SIOPV2_REQUEST_PARSE_FAILED`。
 * - `assertValidRPRegistration` が `registration` 未指定・DID 非対応・署名アルゴリズム非対応を
 *   `4002 RP_REGISTRATION_INVALID` で拒否する。
 * - `processSIOPv2Request` が DID を `sub`、`client_id` を `aud`、`nonce` をそのまま持つ ID Token を
 *   署名鍵の公開鍵で検証可能な形で発行する。
 */

import { describe, expect, test } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getP256PublicKey, verifyP256 } from '../../../keymanager/signer.js';
import { generateIDToken } from '../id-token.js';
import { parseSIOPv2Request } from '../parse.js';
import { processSIOPv2Request } from '../process.js';
import { assertValidRPRegistration } from '../rp-registration.js';
import type { SIOPv2Request } from '../types.js';

const PRIVATE_KEY = new Uint8Array(32).fill(11);
const SIGNER = createPrivateKeySigner(PRIVATE_KEY, 'ES256');
const HOLDER_DID = 'did:key:z6MkHolderTest';
const NOW = 1_700_000_000;

const REGISTRATION_JSON = JSON.stringify({
  subject_syntax_types_supported: ['did', 'did:key'],
  id_token_signing_alg_values_supported: ['ES256'],
});

function buildRequestUri(overrides: Record<string, string | undefined> = {}): string {
  const params: Record<string, string> = {
    scope: 'openid',
    response_type: 'id_token',
    client_id: 'https://rp.example.com',
    redirect_uri: 'https://rp.example.com/callback',
    nonce: 'n-0S6_WzA2Mj',
    registration: encodeURIComponent(REGISTRATION_JSON),
    ...Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined)),
  };
  for (const key of Object.keys(overrides)) {
    if (overrides[key] === undefined) delete params[key];
  }
  const query = Object.entries(params)
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
  return `siopv2://?${query}`;
}

/** JWT の payload / signingInput / signature を取り出す。 */
function decodeJwt(jwt: string): {
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
} {
  const parts = jwt.split('.');
  const [h, p, s] = parts;
  if (h === undefined || p === undefined || s === undefined) {
    throw new Error('malformed jwt');
  }
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  return { payload, signingInput: `${h}.${p}`, signature: base64urlnopad.decode(s) };
}

describe('parseSIOPv2Request', () => {
  test('必須パラメータを展開する', () => {
    const request = parseSIOPv2Request(buildRequestUri());
    expect(request).toEqual({
      scope: 'openid',
      responseType: 'id_token',
      clientId: 'https://rp.example.com',
      redirectUri: 'https://rp.example.com/callback',
      nonce: 'n-0S6_WzA2Mj',
      registration: {
        subjectSyntaxTypesSupported: ['did', 'did:key'],
        idTokenSigningAlgValuesSupported: ['ES256'],
      },
    });
  });

  test('registration 未指定でも parse は成功する（generation 前提のみ RP_REGISTRATION_INVALID）', () => {
    const request = parseSIOPv2Request(buildRequestUri({ registration: undefined }));
    expect(request.registration).toBeUndefined();
  });

  test.each([
    ['クエリが空', ''],
    ['scope が openid を含まない', buildRequestUri({ scope: 'profile' })],
    ['response_type が id_token を含まない', buildRequestUri({ response_type: 'code' })],
    ['client_id 欠落', buildRequestUri({ client_id: undefined })],
    ['redirect_uri 欠落', buildRequestUri({ redirect_uri: undefined })],
    ['nonce 欠落', buildRequestUri({ nonce: undefined })],
    [
      'redirect_uri が非 HTTPS',
      buildRequestUri({ redirect_uri: 'http://rp.example.com/callback' }),
    ],
    ['redirect_uri が URL として不正', buildRequestUri({ redirect_uri: 'not-a-url' })],
    [
      'client_id と redirect_uri の origin が異なる',
      buildRequestUri({
        client_id: 'https://bank.example',
        redirect_uri: 'https://attacker.example/cb',
      }),
    ],
    [
      'client_id と redirect_uri のポートが異なる',
      buildRequestUri({ redirect_uri: 'https://rp.example.com:8443/callback' }),
    ],
    [
      'redirect_uri が内部ホスト（ID Token の送信先 SSRF）',
      buildRequestUri({
        client_id: 'https://10.0.0.5',
        redirect_uri: 'https://10.0.0.5/cb',
      }),
    ],
    [
      'redirect_uri が localhost',
      buildRequestUri({
        client_id: 'https://localhost',
        redirect_uri: 'https://localhost/cb',
      }),
    ],
    [
      'client_id が DID 形式（origin を検証できない）',
      buildRequestUri({ client_id: 'did:web:rp.example.com' }),
    ],
    [
      'client_id に userinfo を含む（表示 RP の詐称）',
      buildRequestUri({
        client_id: 'https://bank.example@evil.example',
        redirect_uri: 'https://evil.example/cb',
      }),
    ],
  ])('%s は 4001 SIOPV2_REQUEST_PARSE_FAILED', (_label, uri) => {
    expect(() => parseSIOPv2Request(uri)).toThrow(VericertsError);
    try {
      parseSIOPv2Request(uri);
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED);
    }
  });

  test('registration の JSON 構文不正は 4001', () => {
    const uri = buildRequestUri({ registration: 'not-json' });
    try {
      parseSIOPv2Request(uri);
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED);
    }
  });

  test('registration の必須フィールドが文字列配列でなければ 4001', () => {
    const malformed = encodeURIComponent(JSON.stringify({ subject_syntax_types_supported: 'did' }));
    try {
      parseSIOPv2Request(buildRequestUri({ registration: malformed }));
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED);
    }
  });
});

describe('assertValidRPRegistration', () => {
  const base: SIOPv2Request = {
    scope: 'openid',
    responseType: 'id_token',
    clientId: 'https://rp.example.com',
    redirectUri: 'https://rp.example.com/callback',
    nonce: 'n-0S6_WzA2Mj',
  };

  test('registration 未指定は 4002 RP_REGISTRATION_INVALID', () => {
    try {
      assertValidRPRegistration(base, 'ES256');
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.RP_REGISTRATION_INVALID);
    }
  });

  test('subject_syntax_types_supported が DID を含まない場合は 4002', () => {
    const request: SIOPv2Request = {
      ...base,
      registration: {
        subjectSyntaxTypesSupported: ['urn:ietf:params:oauth:jwk-thumbprint'],
        idTokenSigningAlgValuesSupported: ['ES256'],
      },
    };
    try {
      assertValidRPRegistration(request, 'ES256');
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.RP_REGISTRATION_INVALID);
    }
  });

  test('id_token_signing_alg_values_supported が signer の alg を含まない場合は 4002', () => {
    const request: SIOPv2Request = {
      ...base,
      registration: {
        subjectSyntaxTypesSupported: ['did:key'],
        idTokenSigningAlgValuesSupported: ['EdDSA'],
      },
    };
    try {
      assertValidRPRegistration(request, 'ES256');
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.RP_REGISTRATION_INVALID);
    }
  });

  test('DID 対応 + 対応アルゴリズムを含む registration は検証を通過する', () => {
    const registration = {
      subjectSyntaxTypesSupported: ['did', 'did:key'],
      idTokenSigningAlgValuesSupported: ['ES256'],
    };
    const request: SIOPv2Request = { ...base, registration };
    expect(assertValidRPRegistration(request, 'ES256')).toEqual(registration);
  });
});

describe('generateIDToken / processSIOPv2Request', () => {
  test('sub(DID) / aud(client_id) / nonce を設定し、署名鍵の公開鍵で検証できる', async () => {
    const request = parseSIOPv2Request(buildRequestUri());
    const idToken = await generateIDToken(request, HOLDER_DID, SIGNER, { nowSeconds: NOW });

    const { payload, signingInput, signature } = decodeJwt(idToken);
    expect(payload).toMatchObject({
      // SIOPv2: self-issued ID Token は iss === sub（Holder の DID）。
      iss: HOLDER_DID,
      sub: HOLDER_DID,
      aud: 'https://rp.example.com',
      nonce: 'n-0S6_WzA2Mj',
      iat: NOW,
      exp: NOW + 5 * 60,
    });
    expect(payload.sub_jwk).toEqual(SIGNER.publicKeyJwk);

    const digest = sha256(new TextEncoder().encode(signingInput));
    const publicKey = getP256PublicKey(PRIVATE_KEY, false);
    expect(verifyP256(digest, signature, publicKey)).toBe(true);
  });

  test('lifetimeSeconds を指定すると exp に反映される', async () => {
    const request = parseSIOPv2Request(buildRequestUri());
    const idToken = await generateIDToken(request, HOLDER_DID, SIGNER, {
      nowSeconds: NOW,
      lifetimeSeconds: 120,
    });
    const { payload } = decodeJwt(idToken);
    expect(payload.exp).toBe(NOW + 120);
  });

  test('processSIOPv2Request は parse → RP 登録検証 → ID Token 生成を一括で行い、redirectUri も返す', async () => {
    const response = await processSIOPv2Request(buildRequestUri(), HOLDER_DID, SIGNER, {
      nowSeconds: NOW,
    });
    expect(response.redirectUri).toBe('https://rp.example.com/callback');
    const { payload } = decodeJwt(response.idToken);
    expect(payload.sub).toBe(HOLDER_DID);
    expect(payload.aud).toBe('https://rp.example.com');
  });

  test('registration が RP 要件を満たさない場合は 4002 を伝播する', async () => {
    const uri = buildRequestUri({
      registration: encodeURIComponent(
        JSON.stringify({
          subject_syntax_types_supported: ['did'],
          id_token_signing_alg_values_supported: ['EdDSA'],
        }),
      ),
    });
    await expect(
      processSIOPv2Request(uri, HOLDER_DID, SIGNER, { nowSeconds: NOW }),
    ).rejects.toMatchObject({
      code: ErrorCodes.RP_REGISTRATION_INVALID,
    });
  });

  test('Request のパースに失敗した場合は 4001 を伝播する', async () => {
    await expect(
      processSIOPv2Request(buildRequestUri({ nonce: undefined }), HOLDER_DID, SIGNER, {
        nowSeconds: NOW,
      }),
    ).rejects.toMatchObject({ code: ErrorCodes.SIOPV2_REQUEST_PARSE_FAILED });
  });
});
