/**
 * Token Request の Attestation-Based Client Authentication の挙動テスト。
 *
 * Token Request も PAR と同じ `client_assertion=<WUA>~<WUA-PoP>` を送る。
 * RFC 9126 §2 のとおり両経路のクライアント認証は同一に扱う。ここでは
 * `oid4vci-par.test.ts` が PAR について固定しているのと同じ不変条件が Token 経路でも成り立つことを
 * 検証する: 対でのみ送ること、`client_assertion_type` 欠落は送信前に 8010 で拒否すること、
 * 任意フィールドを own 限定で読むこと、`client_assertion` 指定時は HTTPS を必須とすること。
 *
 * 末尾の describe は `requestTokenPreAuthorized`（pre-authorized_code 経路）でも
 * 同じクライアント認証条件が適用されることを確認する。判定・送出は
 * `oid4vci-client-auth.ts` を両経路で共有するため定数・ヘルパーを再利用する
 * （`redirectUri` / `clientId` を持たないリクエストでも `expectNoOptionalParams` の
 * 該当チェックは常に真で無害）。
 *
 * 本テストを `internal/auth/__tests__/oid4vci/oid4vci-token.test.ts` ではなく本ディレクトリに置くのは、
 * 追加すると同ファイルが `.linterly.yml` の 300 行上限を超えるため。
 *
 * 本ファイルは `fetchImpl` DI シーム追加より前に書かれており、既存の token テストと
 * 同じくグローバル `fetch` を差し替え `afterEach` で復元する。未注入時の既定経路を通す回帰テストと
 * してこの形のまま残す（DI シーム自体の検証は `oid4vci-token.fetch-di.test.ts`）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { WUA_CLIENT_ASSERTION_TYPE } from '../../../../eudi/wua/types.js';
import {
  requestTokenAuthorizationCode,
  requestTokenPreAuthorized,
} from '../../token/oid4vci-token.js';
import { type FetchCall, stubFetchOk } from './token-fixtures.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

/** Wallet Attestation を使う場合の `client_assertion`（`<WUA>~<WUA-PoP>`）に相当するサンプル。 */
const CLIENT_ASSERTION = 'eyJ.wua.jwt~eyJ.wua.pop';

/**
 * 攻撃者が `Object.prototype` に仕込む任意フィールドの汚染値。正当な値の定数
 * （`CLIENT_ASSERTION` / `WUA_CLIENT_ASSERTION_TYPE`）は使わず、攻撃者由来だと一目で分かる値に
 * する（`oid4vci-par.pollution.test.ts` と同方針。正当な値と同じ定数を使うと「正当な形式だから
 * 通った／弾かれた」の取り違えが起きる）。ここで固定するのは「汚染値は形式によらず一切
 * 採用されない」ことである。
 */
const ATTACKER_OPTIONAL_FIELDS = {
  clientAssertion: 'eyJ.attacker.assertion',
  clientAssertionType: 'urn:attacker:client-assertion-type',
  redirectUri: 'https://attacker.example.com/cb',
  clientId: 'attacker-client',
} as const;

/** 任意フィールド由来のワイヤパラメータが 1 つも body に載っていないこと。 */
function expectNoOptionalParams(body: URLSearchParams | undefined): void {
  expect(body?.has('client_assertion')).toBe(false);
  expect(body?.has('client_assertion_type')).toBe(false);
  expect(body?.has('redirect_uri')).toBe(false);
  expect(body?.has('client_id')).toBe(false);
}

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('requestTokenAuthorizationCode のクライアント認証', () => {
  it('client_assertion と client_assertion_type を対で body に載せる', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'auth-code',
      codeVerifier: 'verifier',
      clientAssertion: CLIENT_ASSERTION,
      clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
    });

    expect(calls[0]?.body.get('client_assertion')).toBe(CLIENT_ASSERTION);
    expect(calls[0]?.body.get('client_assertion_type')).toBe(WUA_CLIENT_ASSERTION_TYPE);
  });

  it.each([
    ['未指定', undefined],
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('client_assertion 指定で client_assertion_type が%sなら 8010 で拒否し fetch を呼ばない', async (_label, assertionType) => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    const promise = requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'auth-code',
      codeVerifier: 'verifier',
      clientAssertion: CLIENT_ASSERTION,
      ...(assertionType === undefined ? {} : { clientAssertionType: assertionType }),
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  it('client_assertion_type だけの指定ではどちらも送らない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'auth-code',
      codeVerifier: 'verifier',
      clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
    });

    expect(calls[0]?.body.has('client_assertion')).toBe(false);
    expect(calls[0]?.body.has('client_assertion_type')).toBe(false);
  });

  // 汚染は共有フィクスチャで**非列挙**（`Object.defineProperty`）に仕込む。実際の汚染攻撃でも
  // 非列挙にできるうえ、列挙可能にするとテストプロセス内の無関係な `for...in` / スプレッドまで
  // 壊れて検証したい経路がぼやけるため（`prototype-pollution.fixtures.ts` の方針）。
  // `obj.prop` / 分割代入 / `??` は列挙可否に関わらず継承値を拾うので、検証したい欠陥は再現する。
  // 汚染下で `await` するため同期版ではなく `*Async` を使う（同期版だと `fn` が返した Promise の
  // 解決前に汚染が戻り、検証したい経路が汚染下で走らずトートロジーになる）。
  it('継承した任意フィールド（データ汚染）は採用しない（own 限定読み）', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    // 任意フィールドを 1 つも指定しない正当な Token Request。鎖読みだと攻撃者の assertion が
    // Wallet のクライアント認証として AS へ送出され、`redirect_uri` / `client_id` も書き換わる。
    await withPollutedPrototypeAsync(ATTACKER_OPTIONAL_FIELDS, () =>
      requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
        code: 'auth-code',
        codeVerifier: 'verifier',
      }),
    );

    expectNoOptionalParams(calls[0]?.body);
  });

  // getter は呼ばれるたびに新しい値を返せるため、「汚染値と `Object.prototype.x` を同一性比較して
  // 除外する」実装はデータ汚染だけを塞いでアクセサ汚染を素通りさせる。両形式を押さえる。
  it('継承した任意フィールド（アクセサ汚染）も採用しない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await withPollutedPrototypeAccessorAsync(
      {
        clientAssertion: () => ATTACKER_OPTIONAL_FIELDS.clientAssertion,
        clientAssertionType: () => ATTACKER_OPTIONAL_FIELDS.clientAssertionType,
        redirectUri: () => ATTACKER_OPTIONAL_FIELDS.redirectUri,
        clientId: () => ATTACKER_OPTIONAL_FIELDS.clientId,
      },
      () =>
        requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
          code: 'auth-code',
          codeVerifier: 'verifier',
        }),
    );

    expectNoOptionalParams(calls[0]?.body);
  });

  it('client_assertion 指定時の http:// エンドポイントは 8010 で拒否し fetch を呼ばない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    const promise = requestTokenAuthorizationCode('http://issuer.example.com/token', {
      code: 'auth-code',
      codeVerifier: 'verifier',
      clientAssertion: CLIENT_ASSERTION,
      clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  it.each([
    'http://issuer.example.com/token',
    'https://127.0.0.1/token',
    'https://169.254.169.254/latest',
    'https://10.0.0.5:8443/x',
  ])('client_assertion 未指定でも %s は 8010 で拒否し fetch を呼ばない', async (endpoint) => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    const promise = requestTokenAuthorizationCode(endpoint, {
      code: 'auth-code',
      codeVerifier: 'verifier',
    });

    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });
});

describe('requestTokenPreAuthorized のクライアント認証', () => {
  const BASE_REQUEST = { preAuthorizedCode: 'pre-auth-code' } as const;

  it('対でのみ送信する（type 単独指定ではどちらも送らない）', async () => {
    const paired: FetchCall[] = [];
    stubFetchOk(paired);
    await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      ...BASE_REQUEST,
      clientAssertion: CLIENT_ASSERTION,
      clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
    });
    expect(paired[0]?.body.get('client_assertion')).toBe(CLIENT_ASSERTION);
    expect(paired[0]?.body.get('client_assertion_type')).toBe(WUA_CLIENT_ASSERTION_TYPE);
    const typeOnly: FetchCall[] = [];
    stubFetchOk(typeOnly);
    await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      ...BASE_REQUEST,
      clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
    });
    expectNoOptionalParams(typeOnly[0]?.body);
  });

  it('client_assertion 指定で client_assertion_type が未指定なら 8010 で拒否し fetch を呼ばない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);
    const promise = requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      ...BASE_REQUEST,
      clientAssertion: CLIENT_ASSERTION,
    });
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  it('継承した任意フィールド（データ/アクセサ汚染）は採用しない（own 限定読み）', async () => {
    const dataCalls: FetchCall[] = [];
    stubFetchOk(dataCalls);
    await withPollutedPrototypeAsync(ATTACKER_OPTIONAL_FIELDS, () =>
      requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_REQUEST),
    );
    expectNoOptionalParams(dataCalls[0]?.body);

    const accessorCalls: FetchCall[] = [];
    stubFetchOk(accessorCalls);
    await withPollutedPrototypeAccessorAsync(
      {
        clientAssertion: () => ATTACKER_OPTIONAL_FIELDS.clientAssertion,
        clientAssertionType: () => ATTACKER_OPTIONAL_FIELDS.clientAssertionType,
      },
      () => requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_REQUEST),
    );
    expectNoOptionalParams(accessorCalls[0]?.body);
  });

  it.each([
    'http://issuer.example.com/token',
    'https://127.0.0.1/token',
    'https://169.254.169.254/latest',
    'https://10.0.0.5:8443/x',
  ])('pre-authorized_code / tx_code を %s へ送らない（8010・fetch 不呼出）', async (endpoint) => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);
    const promise = requestTokenPreAuthorized(endpoint, { ...BASE_REQUEST, txCode: '1234' });
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  it('client_assertion 指定時も同様に非 HTTPS を 8010 で拒否する', async () => {
    const rejected: FetchCall[] = [];
    stubFetchOk(rejected);
    const promise = requestTokenPreAuthorized('http://issuer.example.com/token', {
      ...BASE_REQUEST,
      clientAssertion: CLIENT_ASSERTION,
      clientAssertionType: WUA_CLIENT_ASSERTION_TYPE,
    });
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(rejected).toHaveLength(0);
  });
});
