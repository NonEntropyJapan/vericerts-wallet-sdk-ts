/**
 * ファサード `receiveCredential` の AS mix-up 対策（RFC 9207 / RFC 9700 §4.4）。
 *
 * 攻撃者の Issuer / AS（Offer の `credential_issuer`）が、AS Metadata の `authorization_endpoint` に
 * **正規 AS** を告知し、`token_endpoint` は自分のものにする。ユーザーは正規 AS の本物のログイン画面で
 * 認証し、正規 AS は `state` 付きでコードを Wallet の `redirect_uri` に返す。`iss` を検査しない
 * Wallet は、そのコードと PKCE `code_verifier` を攻撃者の Token Endpoint へ送ってしまう。
 *
 * 認可応答の `iss` が AS Metadata の `issuer` と**完全一致**しない限り、Token Request は
 * 1 度も飛ばない（欠落・不一致・非文字列はすべて fail-closed）ことを固定する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../../../errors.js';
import { receiveCredential } from '../../receive.js';
import {
  AS,
  AS_METADATA_URL,
  asMetadataResponse,
  authorizationCodeDeps,
  authorizationCodeOfferURI,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  PAR_URL,
  parResponse,
  type StubFetch,
  tokenResponse,
} from '../facade-fixtures.js';

const HONEST_AS = 'https://honest-as.example';
const ATTACKER_TOKEN_URL = `${AS}/token`;

/** 攻撃者 AS（`AS`）の Metadata が正規 AS の認可エンドポイントを告知する構成。 */
function mixUpStub(): StubFetch {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () =>
      issuerMetadataResponse({ token_endpoint: undefined, authorization_servers: [AS] }),
    [AS_METADATA_URL]: () =>
      asMetadataResponse({
        authorization_endpoint: `${HONEST_AS}/authorize`,
        token_endpoint: ATTACKER_TOKEN_URL,
      }),
    [PAR_URL]: parResponse,
    [ATTACKER_TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

/** 正規 AS が返す認可応答（`state` は PAR で push された値）。 */
function redirectFrom(stub: StubFetch, extra: Record<string, unknown>) {
  const state = stub.formTo(PAR_URL)?.get('state') ?? '';
  return Promise.resolve({ code: 'HONEST-AS-ISSUED-CODE', state, ...extra });
}

describe('receiveCredential: 認可応答の iss 検証（RFC 9207）', () => {
  test('PoC: 正規 AS が iss=正規 AS を返したら、攻撃者の Token Endpoint へコードを送らず 8010', async () => {
    const stub = mixUpStub();
    const deps = authorizationCodeDeps(stub, {
      authorize: () => redirectFrom(stub, { iss: HONEST_AS }),
    });
    await expect(receiveCredential(authorizationCodeOfferURI(), deps)).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_REQUEST_FAILED,
      context: { reason: 'iss_mismatch' },
    });
    expect(stub.callTo(ATTACKER_TOKEN_URL)).toBeUndefined();
  });

  test('PoC: 正規 AS が RFC 9207 未対応で iss を返さなくても、攻撃者の Token Endpoint へ送らない', async () => {
    const stub = mixUpStub();
    const deps = authorizationCodeDeps(stub, { authorize: () => redirectFrom(stub, {}) });
    await expect(receiveCredential(authorizationCodeOfferURI(), deps)).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_REQUEST_FAILED,
      context: { reason: 'iss_missing' },
    });
    expect(stub.callTo(ATTACKER_TOKEN_URL)).toBeUndefined();
  });

  test('iss が AS Metadata の issuer と完全一致するなら受領できる', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () =>
        issuerMetadataResponse({ token_endpoint: undefined, authorization_servers: [AS] }),
      [AS_METADATA_URL]: () => asMetadataResponse({ token_endpoint: ATTACKER_TOKEN_URL }),
      [PAR_URL]: parResponse,
      [ATTACKER_TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    const deps = authorizationCodeDeps(stub, { authorize: () => redirectFrom(stub, { iss: AS }) });
    const received = await receiveCredential(authorizationCodeOfferURI(), deps);
    expect(received.raw.length).toBeGreaterThan(0);
    expect(stub.formTo(ATTACKER_TOKEN_URL)?.get('code')).toBe('HONEST-AS-ISSUED-CODE');
  });
});
