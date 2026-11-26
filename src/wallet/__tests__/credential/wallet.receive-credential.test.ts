/**
 * Wallet ファサードの `receiveCredential`統合テスト。
 *
 * `receiveCredential` は v1.0 で experimental モジュール関数（`@vericerts/vericerts-wallet-sdk/experimental`）
 * から昇格した `Wallet` メソッドで、`signer` / `holderDid` / `keyId` をアクティブペルソナから
 * 自動解決する点が兄弟の `receivePID(offerURI, opts?)` と同じパターンである。
 *
 * ネットワークは `opts.fetchImpl` の注入のみで再現し、グローバル `fetch` は差し替えない。
 *
 * 受領した VC の既定署名検証のテストは、Linterly の 300 行/ファイル上限のため
 * 別ファイルへ分離している: `wallet.receive-credential.default-verify.test.ts`（SD-JWT / JWT-VC
 * それぞれの正常系・異常系）と `wallet.receive-credential.verify-received-di.test.ts`
 * （`opts.verifyReceived` の読み取り一貫性の回帰テスト）。共有フィクスチャは
 * `receive-credential-fixtures.ts` にある。
 */

import { describe, expect, it } from 'bun:test';
import {
  AS,
  AS_METADATA_URL,
  AUTHZ_URL,
  asMetadataResponse,
  authorizationCodeOfferURI,
  CLIENT_ID,
  CONFIGURATION_ID,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  deferredResponse,
  ISSUER,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  PAR_URL,
  parResponse,
  preAuthorizedOfferURI,
  REDIRECT_URI,
  TOKEN_URL,
  tokenResponse,
} from '../../../internal/auth/oid4vci/facade/__tests__/facade-fixtures.js';
import { ErrorCodes, VericertsError } from '../../../internal/errors.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';
import { setupWallet, TEST_MNEMONIC } from './receive-credential-fixtures.js';

describe('Wallet.receiveCredential（pre-authorized_code 経路）', () => {
  it('signer / holderDid / keyId をアクティブペルソナから解決して受領する', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    const wallet = await setupWallet();

    const vc = await wallet.receiveCredential(preAuthorizedOfferURI(), {
      fetchImpl: stub.fetchImpl,
      // 本テストの主題は OID4VCI フローの配線（アクティブペルソナからの signer / holderDid / keyId
      // 自動解決）であり署名検証ではない。共有フィクスチャの `iss` は DID ではない素の HTTPS URL
      // （`ISSUER`）なので、既定検証を正規の手段である `opts.verifyReceived` で
      // 置換して意図的にオプトアウトする。既定検証自体は別ファイルの専用 describe で検証する。
      verifyReceived: () => {},
    });

    expect(vc.type).toEqual([CONFIGURATION_ID]);
    expect(vc.issuer).toBe(ISSUER);
    expect(vc.format).toBe('sd-jwt');
    expect(vc.claims.degree).toBe('Laurea');
    expect(vc.raw.length).toBeGreaterThan(0);
    // opts に signer / holderDid / keyId を渡していないのに Token Request まで到達している
    // （アクティブペルソナから自動解決された証拠）。
    expect(stub.callTo(ISSUER_METADATA_URL)).toBeDefined();
    expect(stub.callTo(TOKEN_URL)).toBeDefined();
    expect(stub.callTo(CREDENTIAL_URL)).toBeDefined();
  });

  it('遅延発行は VerifiableCredential を返せないため 8020 に倒す', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: deferredResponse,
    });
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl }),
    ).rejects.toMatchObject({
      code: ErrorCodes.CREDENTIAL_REQUEST_FAILED,
      context: { reason: 'deferred_not_supported' },
    });
  });

  it('アクティブペルソナ未設定は PERSONA_NOT_FOUND(2005)', async () => {
    const stub = createStubFetch({});
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    // ペルソナを作らず・アクティブ化せずに呼ぶ。

    let thrown: unknown;
    try {
      await wallet.receiveCredential(preAuthorizedOfferURI(), { fetchImpl: stub.fetchImpl });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.PERSONA_NOT_FOUND);
    // アクティブペルソナ解決より前で失敗するため、HTTP は 1 度も発生しない。
    expect(stub.calls).toHaveLength(0);
  });
});

describe('Wallet.receiveCredential（authorization_code 経路）', () => {
  it('opts.authorize / clientId / redirectUri を渡して受領する', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
      [AS_METADATA_URL]: () => asMetadataResponse(),
      [PAR_URL]: parResponse,
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    const wallet = await setupWallet();

    const vc = await wallet.receiveCredential(authorizationCodeOfferURI(), {
      fetchImpl: stub.fetchImpl,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      authorize: (url) => {
        void url;
        const state = stub.formTo(PAR_URL)?.get('state') ?? '';
        return Promise.resolve({ code: 'authz-code-value', state, iss: AS });
      },
      // 主題は authorization_code 経路（PAR + PKCE）の配線であり署名検証ではないため、上と同じく
      // `opts.verifyReceived` で既定検証を置換してオプトアウトする。
      verifyReceived: () => {},
    });

    expect(vc.format).toBe('sd-jwt');
    expect(stub.callTo(PAR_URL)).toBeDefined();
    expect(stub.callTo(AUTHZ_URL)).toBeUndefined();
  });

  it('opts.authorize 未指定は認可のスキップではなく 8010 で fail-closed', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
    });
    const wallet = await setupWallet();

    await expect(
      wallet.receiveCredential(authorizationCodeOfferURI(), {
        fetchImpl: stub.fetchImpl,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
      }),
    ).rejects.toMatchObject({
      code: ErrorCodes.TOKEN_REQUEST_FAILED,
      context: { reason: 'missing_authorize' },
    });
  });
});
