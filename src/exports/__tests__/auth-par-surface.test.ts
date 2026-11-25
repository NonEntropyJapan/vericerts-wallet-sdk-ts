/**
 * PAR の関数 pushAuthorizationRequest と入力・応答型は実験的な API として
 * vericerts-wallet-sdk/experimental から公開する。公開入口から型を参照し、関数を実際に呼び出す。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';
// 被テスト API は必ず公開バレル（`sdk`）から取る。この import は
// `client_assertion` のサンプル値をテスト間で二重定義しないための共有フィクスチャのみ。
import { WALLET_ATTESTATION_CLIENT_ASSERTION } from '../../internal/auth/oid4vci/__tests__/par/par-fixtures.js';
import { createPrivateKeySigner } from '../../internal/credential/vc/signer.js';
import * as experimental from '../experimental.js';

const PAR_ENDPOINT = 'https://issuer.example.com/par';
const AUTHORIZATION_ENDPOINT = 'https://issuer.example.com/authorize';
const TOKEN_ENDPOINT = 'https://issuer.example.com/token';
const AS_ISSUER = 'https://as.example.com';
const CREDENTIAL_ENDPOINT = 'https://issuer.example.com/credential';

/** CSRF 防止 state（128-bit 以上の乱数）。 */
const STATE = 'Zm9vYmFyLXN0YXRlLTEyOGJpdA';

const VALID_PAR_BODY = {
  request_uri: 'urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c',
  expires_in: 60,
} as const;

/** 成功レスポンスを返す fetch スタブ。送信 body を `calls` に記録する。 */
function stubFetchOk(calls: URLSearchParams[]): experimental.PARRequest['fetchImpl'] {
  return async (_url, init) => {
    calls.push(new URLSearchParams(init.body));
    return new Response(JSON.stringify(VALID_PAR_BODY), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  };
}

describe('公開エクスポート: PAR', () => {
  test('pushAuthorizationRequest が experimental サブパスから import できる', () => {
    expect(typeof experimental.pushAuthorizationRequest).toBe('function');
    // メインバレルには載らない。
    expect((sdk as unknown as Record<string, unknown>).pushAuthorizationRequest).toBeUndefined();
  });

  test('PARRequest / PARResponse / OAuth2AuthzDetails が公開型として使える', async () => {
    const calls: URLSearchParams[] = [];
    const details: readonly experimental.OAuth2AuthzDetails[] = [
      { type: 'openid_credential', credential_configuration_id: 'UniversityDegree' },
    ];
    const req: experimental.PARRequest = {
      par_endpoint: PAR_ENDPOINT,
      client_id: 'wallet-client',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      redirect_uri: 'com.example.wallet://cb',
      state: STATE,
      authorization_details: details,
      fetchImpl: stubFetchOk(calls),
    };

    // 型だけの再エクスポートではなく、公開関数が実際に動作する。
    const res: experimental.PARResponse = await experimental.pushAuthorizationRequest(req);
    expect(res.request_uri).toBe(VALID_PAR_BODY.request_uri);
    expect(res.expires_in).toBe(60);

    const body = calls[0];
    expect(body?.get('client_id')).toBe('wallet-client');
    expect(body?.get('authorization_details')).toBe(JSON.stringify(details));
    expect(body?.get('state')).toBe(STATE);
  });

  test('公開関数のエラーも公開エラーコードに正規化される（非 HTTPS エンドポイント）', async () => {
    const promise = experimental.pushAuthorizationRequest({
      par_endpoint: 'http://issuer.example.com/par',
      client_id: 'wallet-client',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      redirect_uri: 'com.example.wallet://cb',
      state: STATE,
    });
    await expect(promise).rejects.toMatchObject({ code: sdk.ErrorCodes.TOKEN_REQUEST_FAILED });
  });
});

describe('公開エクスポート: buildAuthorizationUrl', () => {
  test('buildAuthorizationUrl が experimental サブパスから import できる', () => {
    expect(typeof experimental.buildAuthorizationUrl).toBe('function');
    // メインバレルには載らない。
    expect((sdk as unknown as Record<string, unknown>).buildAuthorizationUrl).toBeUndefined();
  });

  test('pushAuthorizationRequest の結果から認可 URL を組み立てられる', async () => {
    const calls: URLSearchParams[] = [];
    const res = await experimental.pushAuthorizationRequest({
      par_endpoint: PAR_ENDPOINT,
      client_id: 'wallet-client',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      redirect_uri: 'com.example.wallet://cb',
      state: STATE,
      fetchImpl: stubFetchOk(calls),
    });

    // PAR を叩けるが結果を使えない、という中途半端な公開面になっていないこと。
    const url = experimental.buildAuthorizationUrl(
      AUTHORIZATION_ENDPOINT,
      'wallet-client',
      res.request_uri,
    );
    const params = new URL(url).searchParams;
    expect(params.get('client_id')).toBe('wallet-client');
    expect(params.get('request_uri')).toBe(VALID_PAR_BODY.request_uri);
  });

  test('公開バレル経由でも HTTPS 強制と空文字検証が働く', () => {
    // 利用者が自前で URL を組み立てると迂回してしまうガードが、公開面でも維持されている。
    expect(() =>
      experimental.buildAuthorizationUrl('http://as.example.com/authorize', 'c', 'urn:req:1'),
    ).toThrow();
    expect(() =>
      experimental.buildAuthorizationUrl(AUTHORIZATION_ENDPOINT, '', 'urn:req:1'),
    ).toThrow();
    expect(() => experimental.buildAuthorizationUrl(AUTHORIZATION_ENDPOINT, 'c', '  ')).toThrow();
  });
});

describe('公開エクスポート: client_assertion_type の標準値', () => {
  test('WUA_CLIENT_ASSERTION_TYPE が RFC 7521 §4.2 の絶対 URI である', () => {
    // 以前の `wallet_attestation+jwt` は URI ですらなく、この検査で落ちる。
    // PAR 経路も Token Request 経路も同じ公開定数を使う（同一値の公開名を増やさない）。
    expect(experimental.WUA_CLIENT_ASSERTION_TYPE).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation',
    );
    expect(() => new URL(experimental.WUA_CLIENT_ASSERTION_TYPE)).not.toThrow();
  });

  test('SDK は client_assertion_type を既定値補完せず、明示した値をそのまま送る', async () => {
    const calls: URLSearchParams[] = [];
    await experimental.pushAuthorizationRequest({
      par_endpoint: PAR_ENDPOINT,
      client_id: 'wallet-client',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      redirect_uri: 'com.example.wallet://cb',
      state: STATE,
      client_assertion: WALLET_ATTESTATION_CLIENT_ASSERTION,
      client_assertion_type: experimental.WUA_CLIENT_ASSERTION_TYPE,
      fetchImpl: stubFetchOk(calls),
    });
    expect(calls[0]?.get('client_assertion_type')).toBe(experimental.WUA_CLIENT_ASSERTION_TYPE);

    // client_assertion があるのに type を省くと、既定値で補われず 8010 で拒否される。
    await expect(
      experimental.pushAuthorizationRequest({
        par_endpoint: PAR_ENDPOINT,
        client_id: 'wallet-client',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        redirect_uri: 'com.example.wallet://cb',
        state: STATE,
        client_assertion: WALLET_ATTESTATION_CLIENT_ASSERTION,
        fetchImpl: stubFetchOk(calls),
      }),
    ).rejects.toThrow();
  });
});

describe('公開エクスポート: receiveCredentialViaAuthorizationCode', () => {
  test('receiveCredentialViaAuthorizationCode が experimental サブパスから import できる', () => {
    expect(typeof experimental.receiveCredentialViaAuthorizationCode).toBe('function');
    // ファサード公開範囲は experimental のまま据え置く。
    expect(
      (sdk as unknown as Record<string, unknown>).receiveCredentialViaAuthorizationCode,
    ).toBeUndefined();
  });

  test('公開 receiveCredentialViaAuthorizationCode が実装済みの PAR を実際に呼ぶ（未配線の解消）', async () => {
    // PAR は以前から実装・公開済みだが、それを呼ぶプロダクションフローが無かった。
    // 公開面から 1 本呼ぶだけで PAR エンドポイントに push が飛ぶことを固定する。
    const urls: string[] = [];
    const parBodies: URLSearchParams[] = [];
    const fetchImpl: experimental.PARRequest['fetchImpl'] = async (url, init) => {
      urls.push(url);
      if (url === PAR_ENDPOINT) {
        parBodies.push(new URLSearchParams(init.body));
        return new Response(JSON.stringify(VALID_PAR_BODY), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === TOKEN_ENDPOINT) {
        return new Response(
          JSON.stringify({
            access_token: 'at',
            token_type: 'Bearer',
            expires_in: 3600,
            c_nonce: 'cn',
            c_nonce_expires_in: 300,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response(JSON.stringify({ credential: 'vc-jwt' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    const options: experimental.AuthorizationCodeFlowOptions = {
      endpoints: {
        parEndpoint: PAR_ENDPOINT,
        authorizationEndpoint: AUTHORIZATION_ENDPOINT,
        tokenEndpoint: TOKEN_ENDPOINT,
        credentialEndpoint: CREDENTIAL_ENDPOINT,
      },
      credentialIssuer: 'https://issuer.example.com',
      authorizationServerIssuer: AS_ISSUER,
      clientId: 'wallet-client',
      redirectUri: 'com.example.wallet://cb',
      format: 'dc+sd-jwt',
      credentialDefinition: { type: ['UniversityDegree'] },
    };
    const authorizationUrls: string[] = [];
    const deps: experimental.AuthorizationCodeFlowDeps = {
      signer: createPrivateKeySigner(new Uint8Array(32).fill(9), 'ES256'),
      holderDid: 'did:key:z6MkTest',
      keyId: 'did:key:z6MkTest#key-1',
      fetchImpl,
      authorize: async (url) => {
        authorizationUrls.push(url);
        return { code: 'authz-code', state: parBodies[0]?.get('state') ?? '', iss: AS_ISSUER };
      },
    };

    const result = await experimental.receiveCredentialViaAuthorizationCode(options, deps);
    expect(result.status).toBe('issued');
    expect(urls).toEqual([PAR_ENDPOINT, TOKEN_ENDPOINT, CREDENTIAL_ENDPOINT]);
    // 認可 URL は PAR が払い出した request_uri を使う（RFC 9126）。
    expect(authorizationUrls[0]).toContain(encodeURIComponent(VALID_PAR_BODY.request_uri));
  });
});
