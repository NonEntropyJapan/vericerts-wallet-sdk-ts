/**
 * 回帰テスト: `Wallet.receiveCredential` は `opts` を `{ ...opts }` で複製しない。
 *
 * 修正前は `{ ...opts }` が own かつ列挙可能なプロパティしか複製しないため、クラスインスタンスの
 * プロトタイプメソッド（`authorize` / `createDpopProof` / `verifyReceived` / `fetchImpl`）が落ちていた。
 * `createDpopProof` が落ちると DPoP proof なしの Bearer で進み、`fetchImpl` が落ちると注入した
 * （証明書ピンニング付きの）fetch が無言でグローバル `fetch` に差し替わる。
 * ここでは 4 つ全てをプロトタイプメソッドで DI し、実際に呼ばれること・`this` が元の
 * インスタンスであること・グローバル `fetch` に落ちないこと・DPoP で送られることを固定する。
 *
 * `Object.prototype` 汚染の拒否は `wallet.receive-credential.proto-pollution.test.ts`、純データの
 * プロトタイプ値と Wallet 解決値の優先は `wallet.receive-credential.resolved-values.test.ts`。
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import {
  AS,
  AS_METADATA_URL,
  asMetadataResponse,
  authorizationCodeOfferURI,
  CLIENT_ID,
  CREDENTIAL_URL,
  createStubFetch,
  credentialResponse,
  ISSUER_METADATA_URL,
  issuerMetadataResponse,
  PAR_URL,
  parResponse,
  preAuthorizedOfferURI,
  REDIRECT_URI,
  type StubFetch,
  TOKEN_URL,
  tokenResponse,
} from '../../../../internal/auth/oid4vci/facade/__tests__/facade-fixtures.js';
import type { FetchLike } from '../../../../internal/fetch-di.js';
import { setupWallet } from '../receive-credential-fixtures.js';

type Stub = StubFetch;

function authorizationCodeStub(): Stub {
  return createStubFetch({
    [ISSUER_METADATA_URL]: () => issuerMetadataResponse({ authorization_servers: [AS] }),
    [AS_METADATA_URL]: () => asMetadataResponse(),
    [PAR_URL]: parResponse,
    [TOKEN_URL]: tokenResponse('DPoP'),
    [CREDENTIAL_URL]: credentialResponse,
  });
}

/** 4 つの関数 DI を全てプロトタイプメソッドで持つ（own プロパティは `stub` だけ）。 */
class ClassOpts {
  readonly receivers: Record<string, unknown[]> = {
    authorize: [],
    createDpopProof: [],
    verifyReceived: [],
    fetchImpl: [],
  };
  readonly clientId = CLIENT_ID;
  readonly redirectUri = REDIRECT_URI;
  constructor(readonly stub: Stub) {}

  authorize(
    _url: string,
  ): Promise<{ readonly code: string; readonly state: string; readonly iss: string }> {
    this.receivers.authorize?.push(this);
    const state = this.stub.formTo(PAR_URL)?.get('state') ?? '';
    return Promise.resolve({ code: 'authz-code-value', state, iss: AS });
  }

  createDpopProof(htu: string): string {
    this.receivers.createDpopProof?.push(this);
    return `dpop-proof-for-${htu}`;
  }

  verifyReceived(_raw: string): void {
    this.receivers.verifyReceived?.push(this);
  }

  fetchImpl(...args: Parameters<FetchLike>): ReturnType<FetchLike> {
    this.receivers.fetchImpl?.push(this);
    return this.stub.fetchImpl(...args);
  }
}

describe('Wallet.receiveCredential（クラスインスタンス DI）', () => {
  const realFetch = globalThis.fetch;
  let globalFetchCalls: string[];

  beforeEach(() => {
    globalFetchCalls = [];
    // グローバル fetch に落ちたら観測できるよう、呼ばれたら失敗するスタブに差し替える。
    globalThis.fetch = ((input: unknown) => {
      globalFetchCalls.push(String(input));
      throw new Error('global fetch must not be used');
    }) as unknown as typeof fetch;
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it('authorize / createDpopProof / verifyReceived / fetchImpl の全てがプロトタイプメソッドでも呼ばれ、this は元のインスタンス', async () => {
    const stub = authorizationCodeStub();
    const opts = new ClassOpts(stub);
    const wallet = await setupWallet();

    const vc = await wallet.receiveCredential(authorizationCodeOfferURI(), opts);

    expect(vc.format).toBe('sd-jwt');
    for (const [name, receivers] of Object.entries(opts.receivers)) {
      expect(receivers.length, `${name} が呼ばれた`).toBeGreaterThan(0);
      for (const receiver of receivers) {
        expect(receiver, `${name} の this`).toBe(opts);
      }
    }
    // 注入した fetchImpl だけが使われ、グローバル fetch には 1 度も落ちない。
    expect(globalFetchCalls).toEqual([]);
    expect(stub.callTo(CREDENTIAL_URL)).toBeDefined();
  });

  it('createDpopProof が効き、Token / Credential の要求が DPoP で送られる（Bearer に落ちない）', async () => {
    const stub = authorizationCodeStub();
    const wallet = await setupWallet();

    await wallet.receiveCredential(authorizationCodeOfferURI(), new ClassOpts(stub));

    expect(stub.callTo(TOKEN_URL)?.headers.DPoP).toBe(`dpop-proof-for-${TOKEN_URL}`);
    const credentialCall = stub.callTo(CREDENTIAL_URL);
    expect(credentialCall?.headers.Authorization).toStartWith('DPoP ');
    expect(credentialCall?.headers.DPoP).toBe(`dpop-proof-for-${CREDENTIAL_URL}`);
  });

  it('pre-authorized_code の Offer でも createDpopProof / verifyReceived / fetchImpl が呼ばれる', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse('DPoP'),
      [CREDENTIAL_URL]: credentialResponse,
    });
    const opts = new ClassOpts(stub);
    const wallet = await setupWallet();

    await wallet.receiveCredential(preAuthorizedOfferURI(), opts);

    expect(opts.receivers.authorize).toEqual([]);
    for (const name of ['createDpopProof', 'verifyReceived', 'fetchImpl'] as const) {
      expect(opts.receivers[name]?.every((r) => r === opts)).toBe(true);
      expect(opts.receivers[name]?.length).toBeGreaterThan(0);
    }
    expect(stub.callTo(CREDENTIAL_URL)?.headers.DPoP).toBe(`dpop-proof-for-${CREDENTIAL_URL}`);
    expect(globalFetchCalls).toEqual([]);
  });

  it('継承（Object.create）した fetchImpl も採用され、this は opts になる', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    const receivers: unknown[] = [];
    const base = {
      fetchImpl(this: unknown, ...args: Parameters<FetchLike>): ReturnType<FetchLike> {
        receivers.push(this);
        return stub.fetchImpl(...args);
      },
    };
    const opts = Object.create(base) as Record<string, unknown>;
    opts.verifyReceived = () => {};
    const wallet = await setupWallet();

    await wallet.receiveCredential(preAuthorizedOfferURI(), opts);

    expect(receivers.length).toBeGreaterThan(0);
    expect(receivers.every((r) => r === opts)).toBe(true);
    expect(globalFetchCalls).toEqual([]);
  });
});

describe('Wallet.receiveCredential（fetchImpl がグローバル fetch そのもの）', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it('this を束縛せずに呼ぶ（ブラウザの Illegal invocation 回避）', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    const receivers: unknown[] = [];
    globalThis.fetch = function (this: unknown, ...args: Parameters<FetchLike>) {
      receivers.push(this);
      return stub.fetchImpl(...args);
    } as unknown as typeof fetch;
    const wallet = await setupWallet();

    await wallet.receiveCredential(preAuthorizedOfferURI(), {
      fetchImpl: globalThis.fetch as unknown as FetchLike,
      verifyReceived: () => {},
    });

    expect(receivers.length).toBeGreaterThan(0);
    // 束縛すると `opts` や facade の deps が this になる。グローバル fetch は常に this なしで呼ぶ。
    expect(receivers.every((r) => r === undefined)).toBe(true);
  });
});

describe('Wallet.receiveCredential（DI キーは 1 回だけ読む）', () => {
  it('own アクセサの DI キーは receiveCredential 1 回につき 1 度しか評価されない', async () => {
    const stub = createStubFetch({
      [ISSUER_METADATA_URL]: () => issuerMetadataResponse(),
      [TOKEN_URL]: tokenResponse(),
      [CREDENTIAL_URL]: credentialResponse,
    });
    const reads: Record<string, number> = {};
    const counted = (key: string, value: unknown) => ({
      enumerable: true,
      get() {
        reads[key] = (reads[key] ?? 0) + 1;
        return value;
      },
    });
    const opts = Object.defineProperties(
      {},
      {
        fetchImpl: counted('fetchImpl', stub.fetchImpl),
        verifyReceived: counted('verifyReceived', () => {}),
        createDpopProof: counted('createDpopProof', undefined),
        authorize: counted('authorize', undefined),
        txCode: counted('txCode', undefined),
      },
    );
    const wallet = await setupWallet();

    await wallet.receiveCredential(preAuthorizedOfferURI(), opts);

    // 2 回読むと、1 回目と 2 回目で別の値を返すアクセサに検証と使用の間で差し替えられる。
    expect(reads).toEqual({
      fetchImpl: 1,
      verifyReceived: 1,
      createDpopProof: 1,
      authorize: 1,
      txCode: 1,
    });
  });
});
