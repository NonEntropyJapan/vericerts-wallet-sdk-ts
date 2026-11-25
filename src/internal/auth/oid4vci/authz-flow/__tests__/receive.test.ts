/**
 * `receiveCredentialViaAuthorizationCode`（OID4VCI Authorization Code Flow: PAR + PKCE）の統合テスト。
 *
 * PAR と PKCE を使う Authorization Code Flow を検証する。
 * PAR 自体は以前から実装済みで、欠けていたのは**それを呼ぶフロー**だったため、ここでの回帰の
 * 要点は「実装済みの PAR がプロダクションフローから実際に呼ばれ、PAR、認可、Token Request、Credential Request が 1 本に
 * 繋がっていること」である。各手順のワイヤ形式（PAR body / 認可 URL / Token body /
 * Credential Request）を実際の送信内容で固定する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { receiveCredentialViaAuthorizationCode } from '../receive.js';
import {
  ACCESS_TOKEN,
  AUTHZ_URL,
  C_NONCE,
  CLIENT_ID,
  CREDENTIAL,
  CREDENTIAL_URL,
  createHappyStub,
  createStubFetch,
  credentialResponse,
  deferredResponse,
  dpopTokenResponse,
  flowDeps,
  flowOptions,
  HOLDER_DID,
  HOLDER_KEY_ID,
  ISSUER,
  PAR_REQUEST_URI,
  PAR_URL,
  parResponse,
  REDIRECT_URI,
  TOKEN_URL,
  tokenResponse,
} from './flow-fixtures.js';

/** `BASE64URL(SHA256(code_verifier))` を計算する（RFC 7636 S256 の検算）。 */
async function s256(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  return base64urlnopad.encode(new Uint8Array(digest));
}

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const segment = jwt.split('.')[1] ?? '';
  return JSON.parse(new TextDecoder().decode(base64urlnopad.decode(segment)));
}

describe('receiveCredentialViaAuthorizationCode: PAR から Credential Request までの接続', () => {
  it('PAR → 認可 URL → Token → Credential が 1 本に繋がり VC を受領する', async () => {
    const stub = createHappyStub();
    const deps = flowDeps(stub);

    const result = await receiveCredentialViaAuthorizationCode(
      flowOptions({ scope: 'UniversityDegree' }),
      deps,
    );

    expect(result.status).toBe('issued');
    if (result.status === 'issued') {
      expect(result.credential).toBe(CREDENTIAL);
    }
    // 3 経路がこの順に 1 回ずつ呼ばれる（認可 URL はブラウザ側なので HTTP には出ない）。
    expect(stub.calls.map((c) => c.url)).toEqual([PAR_URL, TOKEN_URL, CREDENTIAL_URL]);
  });

  it('PAR body が必要なフィールドを含む形式で送られる（PAR が実際に呼ばれている）', async () => {
    const stub = createHappyStub();
    const details = [
      { type: 'openid_credential', credential_configuration_id: 'UniversityDegree' },
    ];
    await receiveCredentialViaAuthorizationCode(
      flowOptions({ scope: 'UniversityDegree', authorizationDetails: details }),
      flowDeps(stub),
    );

    const body = stub.formTo(PAR_URL);
    expect(body?.get('response_type')).toBe('code');
    expect(body?.get('client_id')).toBe(CLIENT_ID);
    expect(body?.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(body?.get('code_challenge_method')).toBe('S256');
    expect(body?.get('scope')).toBe('UniversityDegree');
    expect(body?.get('authorization_details')).toBe(JSON.stringify(details));
    // state はフローが生成する（呼び出し側に保持させない）。128 bit 以上の乱数を使う。
    const state = body?.get('state') ?? '';
    expect(base64urlnopad.decode(state).length).toBeGreaterThanOrEqual(16);
  });

  it('認可 URL には client_id と request_uri のみが載る（RFC 9126）', async () => {
    const stub = createHappyStub();
    const deps = flowDeps(stub);
    await receiveCredentialViaAuthorizationCode(flowOptions(), deps);

    expect(deps.authorizationUrls).toHaveLength(1);
    const url = new URL(deps.authorizationUrls[0] ?? '');
    expect(`${url.origin}${url.pathname}`).toBe(AUTHZ_URL);
    expect([...url.searchParams.keys()].sort()).toEqual(['client_id', 'request_uri']);
    expect(url.searchParams.get('request_uri')).toBe(PAR_REQUEST_URI);
  });

  it('Token Request が PKCE を満たす（code_verifier が PAR の code_challenge に対応する）', async () => {
    const stub = createHappyStub();
    await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));

    const parBody = stub.formTo(PAR_URL);
    const tokenBody = stub.formTo(TOKEN_URL);
    expect(tokenBody?.get('grant_type')).toBe('authorization_code');
    expect(tokenBody?.get('code')).toBe('authz-code-value');
    expect(tokenBody?.get('client_id')).toBe(CLIENT_ID);
    // PAR で push した redirect_uri と同一を送る（RFC 6749 §4.1.3 の一致検査）。
    expect(tokenBody?.get('redirect_uri')).toBe(REDIRECT_URI);

    const codeVerifier = tokenBody?.get('code_verifier') ?? '';
    expect(codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(await s256(codeVerifier)).toBe(parBody?.get('code_challenge') ?? '');
  });

  it('Credential Request が access_token と c_nonce にバインドした JWT Proof を送る', async () => {
    const stub = createHappyStub();
    await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));

    const call = stub.callTo(CREDENTIAL_URL);
    expect(call?.headers.Authorization).toBe(`Bearer ${ACCESS_TOKEN}`);
    const body = JSON.parse(call?.body ?? '{}');
    expect(body.format).toBe('dc+sd-jwt');
    expect(body.credential_definition).toEqual({ type: ['UniversityDegree'] });
    expect(body.proof.proof_type).toBe('jwt');

    const claims = decodeJwtPayload(body.proof.jwt);
    expect(claims.nonce).toBe(C_NONCE);
    // aud は Credential Issuer Identifier（Credential Endpoint の URL ではない。OID4VCI 1.0 §8.2.1.1）。
    expect(claims.aud).toBe(ISSUER);
    expect(claims.aud).not.toBe(CREDENTIAL_URL);
    expect(claims.iss).toBe(HOLDER_DID);
  });

  it('state / code_verifier は呼び出しごとに変わる（リプレイ・使い回しを防ぐ）', async () => {
    const first = createHappyStub();
    const second = createHappyStub();
    await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(first));
    await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(second));

    expect(first.formTo(PAR_URL)?.get('state')).not.toBe(second.formTo(PAR_URL)?.get('state'));
    expect(first.formTo(TOKEN_URL)?.get('code_verifier')).not.toBe(
      second.formTo(TOKEN_URL)?.get('code_verifier'),
    );
  });

  it('client_assertion は PAR と Token Request の両方に載る（RFC 9126 §2）', async () => {
    const stub = createHappyStub();
    await receiveCredentialViaAuthorizationCode(
      flowOptions({
        clientAssertion: 'wua-jwt~wua-pop-jwt',
        clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation',
      }),
      flowDeps(stub),
    );

    for (const url of [PAR_URL, TOKEN_URL]) {
      const body = stub.formTo(url);
      expect(body?.get('client_assertion')).toBe('wua-jwt~wua-pop-jwt');
      expect(body?.get('client_assertion_type')).toBe(
        'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation',
      );
    }
  });

  it('DPoP proof は送信先ごとに別々に生成され DPoP ヘッダで送られる（RFC 9449 §4.3 / §5）', async () => {
    // Credential Request に DPoP を載せるのは `token_type: "DPoP"` のときだけ。
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: dpopTokenResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    const htus: string[] = [];
    await receiveCredentialViaAuthorizationCode(
      flowOptions(),
      flowDeps(stub, {
        createDpopProof: (htu) => {
          htus.push(htu);
          return `dpop-for-${htu}`;
        },
      }),
    );

    // 1 つの proof を複数経路に載せると AS / Issuer が htu 束縛検証で拒否するため、htu ごとに
    // 生成する。手順 12（Credential Endpoint）も対象である。
    expect(htus).toEqual([PAR_URL, TOKEN_URL, CREDENTIAL_URL]);
    expect(stub.callTo(PAR_URL)?.headers.DPoP).toBe(`dpop-for-${PAR_URL}`);
    expect(stub.callTo(TOKEN_URL)?.headers.DPoP).toBe(`dpop-for-${TOKEN_URL}`);
    expect(stub.callTo(CREDENTIAL_URL)?.headers.DPoP).toBe(`dpop-for-${CREDENTIAL_URL}`);
  });

  it('createDpopProof 未指定なら DPoP ヘッダを出さない', async () => {
    const stub = createHappyStub();
    await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));
    expect(stub.callTo(PAR_URL)?.headers.DPoP).toBeUndefined();
    expect(stub.callTo(TOKEN_URL)?.headers.DPoP).toBeUndefined();
    expect(stub.callTo(CREDENTIAL_URL)?.headers.DPoP).toBeUndefined();
  });

  it('遅延発行応答はそのまま返す', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse,
      [CREDENTIAL_URL]: deferredResponse,
    });
    const result = await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));

    expect(result.status).toBe('deferred');
    if (result.status === 'deferred') {
      expect(result.transactionId).toBe('tx-42');
    }
  });

  it('JWT Proof の kid は deps.keyId から取る（検証側の鍵解決先）', async () => {
    const stub = createHappyStub();
    await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));
    const body = JSON.parse(stub.callTo(CREDENTIAL_URL)?.body ?? '{}');
    const header = JSON.parse(
      new TextDecoder().decode(base64urlnopad.decode(body.proof.jwt.split('.')[0])),
    );
    expect(header.kid).toBe(HOLDER_KEY_ID);
    expect(header.typ).toBe('openid4vci-proof+jwt');
  });
});

describe('receiveCredentialViaAuthorizationCode: JWT Proof の nonce の解決', () => {
  const NONCE_URL = `${ISSUER}/nonce`;
  const bareTokenResponse = (): Response =>
    new Response(
      JSON.stringify({ access_token: ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600 }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  const nonceResponse = (): Response =>
    new Response(JSON.stringify({ c_nonce: 'nonce-from-endpoint' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  const claimsOf = (stub: ReturnType<typeof createStubFetch>): Record<string, unknown> => {
    const body = JSON.parse(stub.callTo(CREDENTIAL_URL)?.body ?? '{}');
    return decodeJwtPayload(body.proof.jwt);
  };

  it('Token Response に c_nonce が無く nonceEndpoint がある → Nonce Endpoint の値が nonce', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: bareTokenResponse,
      [NONCE_URL]: nonceResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    const base = flowOptions();
    await receiveCredentialViaAuthorizationCode(
      { ...base, endpoints: { ...base.endpoints, nonceEndpoint: NONCE_URL } },
      flowDeps(stub),
    );
    expect(claimsOf(stub).nonce).toBe('nonce-from-endpoint');
  });

  it('c_nonce も nonceEndpoint も無い → nonce の無い proof で Credential Request が送られる', async () => {
    const stub = createStubFetch({
      [PAR_URL]: parResponse,
      [TOKEN_URL]: bareTokenResponse,
      [CREDENTIAL_URL]: credentialResponse,
    });
    await receiveCredentialViaAuthorizationCode(flowOptions(), flowDeps(stub));
    expect(Object.hasOwn(claimsOf(stub), 'nonce')).toBe(false);
  });
});
