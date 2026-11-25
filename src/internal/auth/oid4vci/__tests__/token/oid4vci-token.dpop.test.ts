/**
 * Token Request（authorization_code グラント）の DPoP proof 送出テスト
 * （`DPoP=<dpop_jwt>`、RFC 9449 §5）。
 *
 * `POST /token` に DPoP proof を添える場合、RFC 9449 §5 のとおり
 * proof は body ではなく `DPoP` HTTP ヘッダで送る。ここでは PAR 経路
 * （`oid4vci-par.test.ts` の「DPoP proof の送出」「`PARRequest.dpop` の `Object.prototype`
 * 汚染耐性」）と同じ不変条件が Token 経路でも成り立つことを検証する:
 * ヘッダに載ること・body には載らないこと・空値は送信前に 8010 で拒否すること・
 * 未指定ならヘッダ自体を出さないこと・継承値は採用しないこと。
 *
 * 本テストを既存の `oid4vci-token.client-auth.test.ts` / `internal/auth/__tests__/
 * oid4vci-token.test.ts` に足さず新ファイルにしているのは、いずれも追記すると
 * `.linterly.yml` の 1 ファイル 300 行上限を超えるため。
 *
 * 本ファイルは `fetchImpl` DI シーム追加より前に書かれており、既存の token テストと
 * 同じくグローバル `fetch` を差し替え `afterEach` で復元する。未注入時の既定経路を通す回帰テストと
 * してこの形のまま残す（DI シーム自体の検証は `oid4vci-token.fetch-di.test.ts`）。
 * ヘッダを検証するので、共有フィクスチャ（`token-fixtures.ts`）が記録する `init.headers` を読む。
 *
 * `requestTokenPreAuthorized`（pre-authorized_code 経路）も `dpop` を
 * 受け取れるようになった。グラント種別にかかわらず RFC 9449 §5 と同じヘッダを使うことを確認する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import {
  requestTokenAuthorizationCode,
  requestTokenPreAuthorized,
} from '../../token/oid4vci-token.js';
import { type FetchCall, stubFetchOk } from './token-fixtures.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

/** 呼び出し側が `createDpopProof({ htm: 'POST', htu: <tokenEndpoint> }, signer)` で得る proof。 */
const PROOF = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.eyJodG0iOiJQT1NUIn0.c2ln';

/** 攻撃者が `Object.prototype` に仕込む proof（正当な値とは別物だと一目で分かる形にする）。 */
const ATTACKER_PROOF = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.attacker.sig';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** 任意フィールドを何も指定しない最小の authorization_code Token Request。 */
const BASE_REQUEST = { code: 'auth-code', codeVerifier: 'verifier' } as const;

describe('DPoP proof の送出（RFC 9449 §5）', () => {
  it('dpop 指定時は body ではなく DPoP ヘッダに載せる', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenAuthorizationCode(TOKEN_ENDPOINT, { ...BASE_REQUEST, dpop: PROOF });

    expect(calls[0]?.init.headers.DPoP).toBe(PROOF);
    // RFC 9449 §5 は proof を HTTP ヘッダで送ると定める。body に混ぜてはならない。
    expect(calls[0]?.body.has('dpop')).toBe(false);
  });

  it('dpop 未指定なら DPoP ヘッダ自体を出さない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenAuthorizationCode(TOKEN_ENDPOINT, BASE_REQUEST);

    // 空ヘッダを送ると AS が DPoP 利用の意図ありと解釈して形式不正で落としうる。
    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  it.each([
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('dpop が%sなら 8010 で拒否し fetch を呼ばない', async (_label, dpop) => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    const promise = requestTokenAuthorizationCode(TOKEN_ENDPOINT, { ...BASE_REQUEST, dpop });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    // 空の `DPoP` ヘッダは AS 側で形式不正になるだけなので、入口で落として原因を明確にする。
    expect(calls).toHaveLength(0);
  });
});

describe('AuthorizationCodeTokenRequest.dpop の Object.prototype 汚染耐性', () => {
  // 汚染は共有フィクスチャで**非列挙**に仕込む（`prototype-pollution.fixtures.ts` の方針）。
  // 汚染下で `await` するため `*Async` 版を使う（同期版だと `fn` が返した Promise の解決前に
  // 汚染が戻り、検証したい経路が汚染下で走らずトートロジーになる）。
  it('継承した dpop（データ汚染）は DPoP ヘッダに載せない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    // `dpop` を指定していない正当な Token Request。鎖読みだと攻撃者の proof がヘッダで送出され、
    // AS 側で Wallet の鍵束縛が攻撃者の鍵に差し替わる。
    await withPollutedPrototypeAsync({ dpop: ATTACKER_PROOF }, () =>
      requestTokenAuthorizationCode(TOKEN_ENDPOINT, BASE_REQUEST),
    );

    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  // getter は呼ばれるたびに新しい値を返せるため、汚染値との同一性比較では弾けない。
  it('継承した dpop（アクセサ汚染）も DPoP ヘッダに載せない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await withPollutedPrototypeAccessorAsync({ dpop: () => ATTACKER_PROOF }, () =>
      requestTokenAuthorizationCode(TOKEN_ENDPOINT, BASE_REQUEST),
    );

    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  it('汚染下でも明示的に渡した dpop はそのまま DPoP ヘッダに載る（正常系）', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await withPollutedPrototypeAsync({ dpop: ATTACKER_PROOF }, () =>
      requestTokenAuthorizationCode(TOKEN_ENDPOINT, { ...BASE_REQUEST, dpop: PROOF }),
    );

    expect(calls[0]?.init.headers.DPoP).toBe(PROOF);
  });
});

/** 任意フィールドを何も指定しない最小の pre-authorized_code Token Request。 */
const BASE_PRE_AUTH_REQUEST = { preAuthorizedCode: 'pre-auth-code-123' } as const;

describe('DPoP proof の送出（pre-authorized_code 経路、RFC 9449 §5）', () => {
  it('dpop 指定時は body ではなく DPoP ヘッダに載せる', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenPreAuthorized(TOKEN_ENDPOINT, { ...BASE_PRE_AUTH_REQUEST, dpop: PROOF });

    expect(calls[0]?.init.headers.DPoP).toBe(PROOF);
    // RFC 9449 §5 は proof を HTTP ヘッダで送ると定める。body に混ぜてはならない。
    expect(calls[0]?.body.has('dpop')).toBe(false);
  });

  it('proof の htu 束縛先である Token Endpoint へ送る（RFC 9449 §4.3）', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenPreAuthorized(TOKEN_ENDPOINT, { ...BASE_PRE_AUTH_REQUEST, dpop: PROOF });

    // 呼び出し側は `htu = <tokenEndpoint>` で proof を生成する。送信先が第 1 引数と食い違うと
    // AS が §4.3 の HTTP 束縛検証で拒否するため、送信 URL が第 1 引数と一致することを固定する。
    expect(calls[0]?.url).toBe(TOKEN_ENDPOINT);
  });

  it('dpop 未指定なら DPoP ヘッダ自体を出さない（既存呼び出しの挙動を変えない）', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_PRE_AUTH_REQUEST);

    // `calls` が空でも `Object.hasOwn({}, …)` は false になるため、送信が起きたことを先に固定する
    // （空振りだと「ヘッダを出さない」ではなく「そもそも送っていない」を検証してしまう）。
    expect(calls).toHaveLength(1);
    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  it.each([
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('dpop が%sなら 8010 で拒否し fetch を呼ばない', async (_label, dpop) => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    const promise = requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      ...BASE_PRE_AUTH_REQUEST,
      dpop,
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    expect(calls).toHaveLength(0);
  });

  it('継承した dpop（データ汚染）は DPoP ヘッダに載せない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    // `dpop` を指定していない正当な Token Request。鎖読みだと攻撃者の proof がヘッダで送出され、
    // AS 側で Wallet の鍵束縛が攻撃者の鍵に差し替わる。
    await withPollutedPrototypeAsync({ dpop: ATTACKER_PROOF }, () =>
      requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_PRE_AUTH_REQUEST),
    );

    expect(calls).toHaveLength(1);
    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  it('継承した dpop（アクセサ汚染）も DPoP ヘッダに載せない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await withPollutedPrototypeAccessorAsync({ dpop: () => ATTACKER_PROOF }, () =>
      requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_PRE_AUTH_REQUEST),
    );

    expect(calls).toHaveLength(1);
    expect(Object.hasOwn(calls[0]?.init.headers ?? {}, 'DPoP')).toBe(false);
  });

  // ポジティブコントロール。上 2 件が「汚染値を弾いた」ことを示すには、同じ汚染下で**明示指定した
  // proof は通る**ことも示す必要がある（own 限定読みを「常に undefined を返す」実装に退行させても
  // 上 2 件は通ってしまい、過剰に弾いた場合と区別が付かない）。
  it('汚染下でも明示的に渡した dpop はそのまま DPoP ヘッダに載る（正常系）', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await withPollutedPrototypeAsync({ dpop: ATTACKER_PROOF }, () =>
      requestTokenPreAuthorized(TOKEN_ENDPOINT, { ...BASE_PRE_AUTH_REQUEST, dpop: PROOF }),
    );

    expect(calls[0]?.init.headers.DPoP).toBe(PROOF);
  });
});
