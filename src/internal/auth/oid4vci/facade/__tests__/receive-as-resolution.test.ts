/**
 * ファサード `receiveCredential` の Authorization Server 解決（OID4VCI 1.0 §4.1.1）。
 *
 * §4.1.1 は Offer の `grants.authorization_code.authorization_server` が Issuer Metadata の
 * `authorization_servers` の**いずれかと一致する**ことを要求する。照合を省くと、正規の
 * `credential_issuer` と攻撃者の `authorization_server` を組み合わせた Offer で AS Metadata の
 * 取得先が攻撃者になり、`client_assertion`（`<WUA>~<WUA-PoP>`）が攻撃者の PAR エンドポイントへ
 * 送出され、ユーザーのブラウザが攻撃者の `authorization_endpoint` で開く。
 *
 * 併せて「Token Endpoint は AS Metadata の `token_endpoint` を使う」判断も本ファイルで固定する
 * （OID4VCI 1.0 の Issuer Metadata に `token_endpoint` は無い。RFC 6749 §4.1.3）。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { receiveCredential } from '../receive.js';
import {
  AS,
  AS_METADATA_URL,
  AS_TOKEN_URL,
  AUTHZ_URL,
  asMetadataResponse,
  authorizationCodeDeps,
  authorizationCodeOfferURI,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  facadeDeps,
  ISSUER,
  ISSUER_AS_METADATA_URL,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  json,
  PAR_URL,
  parResponse,
  preAuthorizedOfferURI,
  TOKEN_URL,
  tokenResponse,
} from './facade-fixtures.js';

/** 攻撃者が支配する AS。Offer にだけ現れ、Issuer Metadata は告知しない。 */
const EVIL_AS = 'https://evil.example';
const EVIL_AS_METADATA_URL = `${EVIL_AS}/.well-known/oauth-authorization-server`;

/**
 * `authorization_servers` の告知を差し替えたうえで成功経路を張るスタブ。
 *
 * 攻撃者の AS Metadata URL もルートに載せる。載せないと 404 で落ちるため「照合で落ちた」のか
 * 「取得に失敗した」のか区別できず、C1 の回帰テストにならない。
 */
function stubWithAuthorizationServers(
  extra: Readonly<Record<string, unknown>>,
): ReturnType<typeof createStubFetch> {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse(extra),
    [AS_METADATA_URL]: () => asMetadataResponse(),
    [EVIL_AS_METADATA_URL]: () => asMetadataResponse({ issuer: EVIL_AS }),
    [PAR_URL]: parResponse,
    [TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

describe('receiveCredential: authorization_server の告知照合（§4.1.1）', () => {
  test('告知集合に含まれる authorization_server は集合の先頭より優先される', async () => {
    const stub = stubWithAuthorizationServers({
      authorization_servers: ['https://other.example.eu', AS],
    });
    await receiveCredential(
      authorizationCodeOfferURI({ authorization_server: AS }),
      authorizationCodeDeps(stub),
    );
    // 先頭（`https://other.example.eu`）ではなく grant の宣言値が採用される。
    expect(stub.callTo(AS_METADATA_URL)).toBeDefined();
    expect(
      stub.callTo('https://other.example.eu/.well-known/oauth-authorization-server'),
    ).toBeUndefined();
  });

  test('告知に無い authorization_server は 8010 で落ち、その AS へ fetch が 1 度も飛ばない', async () => {
    const stub = stubWithAuthorizationServers({ authorization_servers: [AS] });
    await expect(
      receiveCredential(
        authorizationCodeOfferURI({ authorization_server: EVIL_AS }),
        authorizationCodeDeps(stub),
      ),
    ).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_REQUEST_FAILED,
      context: { reason: 'authorization_server_not_declared' },
    });
    // 攻撃者の Metadata を引かない = PAR / 認可 URL の宛先が攻撃者に化ける余地が無い。
    expect(stub.callTo(EVIL_AS_METADATA_URL)).toBeUndefined();
    expect(stub.callTo(PAR_URL)).toBeUndefined();
  });

  test('authorization_servers が未告知なら宣言値を採用せず 8010（照合できない＝fail-closed）', async () => {
    const stub = stubWithAuthorizationServers({});
    await expect(
      receiveCredential(
        authorizationCodeOfferURI({ authorization_server: AS }),
        authorizationCodeDeps(stub),
      ),
    ).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_REQUEST_FAILED,
      context: { reason: 'authorization_server_not_declared' },
    });
    expect(stub.callTo(AS_METADATA_URL)).toBeUndefined();
  });

  test('末尾スラッシュの有無だけの差異では正当な Offer を落とさない', async () => {
    const stub = stubWithAuthorizationServers({ authorization_servers: [AS] });
    await receiveCredential(
      authorizationCodeOfferURI({ authorization_server: `${AS}/` }),
      authorizationCodeDeps(stub),
    );
    expect(stub.callTo(AS_METADATA_URL)).toBeDefined();
  });

  test('authorization_server の宣言が無ければ告知の先頭を使う', async () => {
    const stub = stubWithAuthorizationServers({
      authorization_servers: [AS, 'https://other.example.eu'],
    });
    await receiveCredential(authorizationCodeOfferURI(), authorizationCodeDeps(stub));
    expect(stub.callTo(AS_METADATA_URL)).toBeDefined();
  });

  test('宣言も告知も無ければ credential_issuer 自身を AS として扱う', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [ISSUER_AS_METADATA_URL]: () =>
        json({
          issuer: ISSUER,
          pushed_authorization_request_endpoint: PAR_URL,
          authorization_endpoint: AUTHZ_URL,
          token_endpoint: TOKEN_URL,
        }),
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    await receiveCredential(
      authorizationCodeOfferURI(),
      authorizationCodeDeps(stub, {
        authorize: () =>
          Promise.resolve({
            code: 'authz-code-value',
            state: stub.formTo(PAR_URL)?.get('state') ?? '',
            iss: ISSUER,
          }),
      }),
    );
    expect(stub.callTo(ISSUER_AS_METADATA_URL)).toBeDefined();
  });
});

describe('receiveCredential: Token Endpoint は AS Metadata の token_endpoint', () => {
  test('authorization_code: Issuer Metadata が別の token_endpoint を持っても AS の値へ code を送る', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
      [AS_METADATA_URL]: () => asMetadataResponse({ token_endpoint: AS_TOKEN_URL }),
      [PAR_URL]: parResponse,
      [AS_TOKEN_URL]: tokenResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    await receiveCredential(authorizationCodeOfferURI(), authorizationCodeDeps(stub));
    // 認可コードを発行した AS 以外（Issuer 側の URL）へ code / code_verifier を流さない。
    expect(stub.callTo(AS_TOKEN_URL)).toBeDefined();
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
  });

  test('authorization_code: Issuer Metadata に token_endpoint が無くても受領できる', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () =>
        json({
          credential_issuer: ISSUER,
          credential_endpoint: CREDENTIAL_URL,
          authorization_servers: [AS],
        }),
      [AS_METADATA_URL]: () => asMetadataResponse({ token_endpoint: AS_TOKEN_URL }),
      [PAR_URL]: parResponse,
      [AS_TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    await receiveCredential(authorizationCodeOfferURI(), authorizationCodeDeps(stub));
    expect(stub.callTo(AS_TOKEN_URL)).toBeDefined();
  });

  test('pre-authorized_code: Issuer と別ホストの AS の token_endpoint へ送り、Issuer Metadata の token_endpoint は不要', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () =>
        json({
          credential_issuer: ISSUER,
          credential_endpoint: CREDENTIAL_URL,
          authorization_servers: [AS],
        }),
      [AS_METADATA_URL]: () => asMetadataResponse({ token_endpoint: AS_TOKEN_URL }),
      [AS_TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    expect(stub.formTo(AS_TOKEN_URL)?.get('pre-authorized_code')).toBe('pre-auth-code-123');
  });

  test('pre-authorized_code: authorization_servers が無ければ credential_issuer を AS として引く', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () =>
        json({ credential_issuer: ISSUER, credential_endpoint: CREDENTIAL_URL }),
      [ISSUER_AS_METADATA_URL]: () => json({ issuer: ISSUER, token_endpoint: TOKEN_URL }),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    expect(stub.callTo(TOKEN_URL)).toBeDefined();
  });

  test('pre-authorized_code: AS Metadata が引けないとき旧 Draft の Issuer token_endpoint へ後方互換で送る', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    expect(stub.callTo(TOKEN_URL)).toBeDefined();
  });

  test('pre-authorized_code: AS Metadata も Issuer token_endpoint も無ければ 3004 で落ち Token Request は飛ばない', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () =>
        json({ credential_issuer: ISSUER, credential_endpoint: CREDENTIAL_URL }),
      [TOKEN_URL]: tokenResponse(),
    });
    await expect(
      receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub)),
    ).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
    });
    expect(stub.callTo(TOKEN_URL)).toBeUndefined();
  });
});
