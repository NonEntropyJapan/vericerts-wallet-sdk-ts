/**
 * ファサード `receiveCredential(offerURI, deps)` の統合テスト。
 *
 * 2 つの発行フロー（Pre-Authorized Code Flow / Authorization Code Flow）が
 * **Offer URI 1 本を入口に**成立することを、実際の HTTP 記録から確認する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { receiveCredential } from '../receive.js';
import {
  AS,
  AS_METADATA_URL,
  asMetadataResponse,
  authorizationCodeDeps,
  authorizationCodeOfferURI,
  CONFIGURATION_ID,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  deferredResponse,
  facadeDeps,
  ISSUER,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  PAR_URL,
  parResponse,
  preAuthorizedOfferURI,
  TOKEN_URL,
  tokenResponse,
} from './facade-fixtures.js';

/** pre-authorized_code 経路が成功するスタブ。 */
function preAuthorizedStub(): ReturnType<typeof createStubFetch> {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
    [TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

/** authorization_code 経路が成功するスタブ（AS は `authorization_servers` で告知）。 */
function authorizationCodeStub(): ReturnType<typeof createStubFetch> {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
    [AS_METADATA_URL]: () => asMetadataResponse(),
    [PAR_URL]: parResponse,
    [TOKEN_URL]: tokenResponse(),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

describe('receiveCredential: pre-authorized_code 経路', () => {
  test('Offer URI 1 引数（+ 依存）で VC を受領し ReceivedVerifiableCredential で返す', async () => {
    const stub = preAuthorizedStub();
    const vc = await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));

    expect(vc.type).toEqual([CONFIGURATION_ID]);
    expect(vc.issuer).toBe(ISSUER);
    expect(vc.format).toBe('sd-jwt');
    expect(vc.claims.degree).toBe('Laurea');
    expect(vc.raw.length).toBeGreaterThan(0);
    expect(vc.issuanceDate).toBe(new Date(1_767_000_000 * 1000).toISOString());
  });

  test('Issuer Metadata を自分で引く（呼び出し側は endpoints を渡さない）', async () => {
    const stub = preAuthorizedStub();
    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub));
    expect(stub.callTo(ISSUER_METADATA_URL)).toBeDefined();
    expect(stub.callTo(TOKEN_URL)?.body).toContain('pre-auth-code-123');
    // pre-authorized 経路では AS Metadata は引かない（PAR も認可も無い）。
    expect(stub.callTo(AS_METADATA_URL)).toBeUndefined();
    expect(stub.callTo(PAR_URL)).toBeUndefined();
  });

  test('遅延発行は VerifiableCredential を返せないため 8020 に倒す', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: deferredResponse,
    });
    await expect(
      receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub)),
    ).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
      context: { reason: 'deferred_not_supported' },
    });
  });
});

describe('receiveCredential: authorization_code 経路', () => {
  test('AS Metadata を引いて PAR + PKCE のフローを通し VC を受領する', async () => {
    const stub = authorizationCodeStub();
    const vc = await receiveCredential(authorizationCodeOfferURI(), authorizationCodeDeps(stub));
    expect(vc.format).toBe('sd-jwt');
    expect(vc.type).toEqual([CONFIGURATION_ID]);
    // 手順 1〜2 の Metadata 解決 → 手順 5 PAR → 手順 10 Token → 手順 12 Credential。
    expect(stub.callTo(ISSUER_METADATA_URL)).toBeDefined();
    expect(stub.callTo(AS_METADATA_URL)).toBeDefined();
    expect(stub.callTo(PAR_URL)).toBeDefined();
    expect(stub.callTo(TOKEN_URL)).toBeDefined();
    expect(stub.callTo(CREDENTIAL_URL)).toBeDefined();
  });

  test('遅延発行の応答は authorization_code 経路でも 8020 に倒す', async () => {
    // `receiveCredentialViaAuthorizationCode` は deferred をそのまま返すため、
    // `VerifiableCredential` を返せないファサード側で落とす分岐がこの経路にも要る。
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
      [AS_METADATA_URL]: () => asMetadataResponse(),
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: deferredResponse,
    });
    await expect(
      receiveCredential(authorizationCodeOfferURI(), authorizationCodeDeps(stub)),
    ).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
      context: { reason: 'deferred_not_supported' },
    });
  });

  test('authorize 未指定は認可のスキップではなく 8010（fail-closed）', async () => {
    const stub = authorizationCodeStub();
    await expect(
      receiveCredential(authorizationCodeOfferURI(), facadeDeps(stub)),
    ).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_REQUEST_FAILED,
      context: { reason: 'missing_authorize' },
    });
    // 認可 UI が無い時点で HTTP を出さない（Metadata 取得より前に落とす経路ではないが、
    // PAR には到達しない）。
    expect(stub.callTo(PAR_URL)).toBeUndefined();
  });

  test('clientId / redirectUri 未指定は 8010', async () => {
    const stub = authorizationCodeStub();
    await expect(
      receiveCredential(
        authorizationCodeOfferURI(),
        facadeDeps(stub, { authorize: () => Promise.resolve({ code: 'c', state: 's' }) }),
      ),
    ).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_REQUEST_FAILED,
      context: { reason: 'missing_client_registration' },
    });
  });
});

describe('receiveCredential: grant の振り分けと fail-closed', () => {
  test('両方の grant を告知する Offer は authorization_code を選ぶ', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
      [AS_METADATA_URL]: () => asMetadataResponse(),
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    const offerURI = `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIGURATION_ID],
        grants: {
          authorization_code: {},
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'pre-auth-code-123',
          },
        },
      }),
    )}`;
    await receiveCredential(offerURI, authorizationCodeDeps(stub));
    // Issuer が認可を要求しているのに Wallet が認可を省く経路を選ばないこと。
    expect(stub.callTo(PAR_URL)).toBeDefined();
  });

  test('grant の告知が無い Offer は 3003（どちらのフローも開始できない）', async () => {
    const stub = preAuthorizedStub();
    const offerURI = `openid-credential-offer://?credential_offer=${encodeURIComponent(
      JSON.stringify({
        credential_issuer: ISSUER,
        credential_configuration_ids: [CONFIGURATION_ID],
      }),
    )}`;
    await expect(receiveCredential(offerURI, facadeDeps(stub))).rejects.toMatchObject({
      code: ErrorCodes.OFFER_URI_PARSE_FAILED,
      context: { reason: 'unsupported_grant' },
    });
  });

  test('signer / holderDid / keyId の欠落は 8010（HTTP を 1 度も出さない）', async () => {
    const stub = preAuthorizedStub();
    await expect(
      receiveCredential(preAuthorizedOfferURI(), {
        holderDid: '',
        keyId: '',
      } as never),
    ).rejects.toThrow(VericertsError);
    expect(stub.calls).toHaveLength(0);
  });
});

describe('receiveCredential: 署名検証フック（3010）', () => {
  test('verifyReceived が throw したら 3010 へ正規化する', async () => {
    const stub = preAuthorizedStub();
    await expect(
      receiveCredential(
        preAuthorizedOfferURI(),
        facadeDeps(stub, {
          verifyReceived: () => {
            throw new Error('bad signature');
          },
        }),
      ),
    ).rejects.toMatchObject({
      code: ErrorCodes.SIG_INVALID,
      context: { reason: 'received_credential_signature_invalid' },
    });
  });

  test('verifyReceived には受領した生 VC が渡り、成功すれば結果を返す', async () => {
    const stub = preAuthorizedStub();
    const seen: string[] = [];
    const vc = await receiveCredential(
      preAuthorizedOfferURI(),
      facadeDeps(stub, {
        verifyReceived: (raw) => {
          seen.push(raw);
        },
      }),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0]).toBe(vc.raw);
  });

  test('verifyReceived 未指定なら 1 度も呼ばれない（呼び出し側の責務）', async () => {
    const stub = preAuthorizedStub();
    const calls: string[] = [];
    const spy = (raw: string): void => {
      calls.push(raw);
    };
    // 同一の spy を「省いた deps」と「プロトタイプ経由で渡した deps」の両方に対して使い、
    // 省いた側で 0 回・渡した側で 1 回になることを対比で示す。回数を見ないと
    // 「検証が走っていても通るテスト」になる。
    const omitted = facadeDeps(stub);
    await receiveCredential(preAuthorizedOfferURI(), omitted);
    expect(calls).toHaveLength(0);

    await receiveCredential(preAuthorizedOfferURI(), facadeDeps(stub, { verifyReceived: spy }));
    expect(calls).toHaveLength(1);
  });

  test('プロトタイプ継承の verifyReceived は採用され、this は deps に束ね直される', async () => {
    const stub = preAuthorizedStub();
    const receivers: unknown[] = [];
    // `class Deps { verifyReceived() {…} }` のようなクラスベース DI が正当なので、
    // `nonObjectPrototypeProperty` はプロトタイプ経由の関数値を意図的に拾う。own 限定で
    // 読むと注入した署名検証が無言でスキップされる（fail-open）。
    const deps = Object.create({
      verifyReceived(this: unknown): void {
        receivers.push(this);
      },
    }) as Record<string, unknown>;
    Object.assign(deps, facadeDeps(stub));

    await receiveCredential(preAuthorizedOfferURI(), deps as never);
    expect(receivers).toHaveLength(1);
    expect(receivers[0]).toBe(deps);
  });
});
