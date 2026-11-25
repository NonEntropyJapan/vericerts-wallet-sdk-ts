/**
 * `PreAuthorizedTokenRequest.txCode` の `Object.prototype` 汚染耐性。
 *
 * `requestTokenPreAuthorized` は `clientAssertion` / `clientAssertionType` / `dpop` を
 * `ownProperty` で own 限定に読む一方、`txCode` だけを鎖読みしていた。
 * `txCode` は**ユーザーが入力する PIN** であり、鎖読みだと `txCode` を指定していない正当な
 * Token Request でも `Object.prototype.txCode` の汚染値が `tx_code` として AS へ送出される。
 *
 * ここでは `txCode` が own 限定で読まれること（データ汚染 / アクセサ汚染の両方）と、明示指定した
 * `txCode` が従来どおり送出されること（ポジティブコントロール）を固定する。
 *
 * 本テストを `oid4vci-token.dpop.test.ts` に足さず新ファイルにしているのは、同ファイルが
 * 既に 255 行あり追記すると `.linterly.yml` の 1 ファイル 300 行上限を超えるため。
 * 汚染テストを独立ファイルに置く形は `oid4vci-par.pollution.test.ts` と同じ。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { requestTokenPreAuthorized } from '../../token/oid4vci-token.js';
import { type FetchCall, stubFetchOk } from './token-fixtures.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

/** 呼び出し側が Offer の `tx_code` に応じてユーザーから受け取る正当な PIN。 */
const TX_CODE = '493536';

/** 攻撃者が `Object.prototype` に仕込む PIN（正当な値とは別物だと一目で分かる形にする）。 */
const ATTACKER_TX_CODE = '000000-attacker';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** 任意フィールドを何も指定しない最小の pre-authorized_code Token Request。 */
const BASE_PRE_AUTH_REQUEST = { preAuthorizedCode: 'pre-auth-code-123' } as const;

describe('PreAuthorizedTokenRequest.txCode の Object.prototype 汚染耐性', () => {
  // 汚染は共有フィクスチャで**非列挙**に仕込む（`prototype-pollution.fixtures.ts` の方針）。
  // 汚染下で `await` するため `*Async` 版を使う（同期版だと `fn` が返した Promise の解決前に
  // 汚染が戻り、検証したい経路が汚染下で走らずトートロジーになる）。
  it('継承した txCode（データ汚染）は tx_code として送出しない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    // `txCode` を指定していない正当な Token Request。鎖読みだと攻撃者が仕込んだ値が
    // ユーザー入力 PIN として AS へ送出される。
    await withPollutedPrototypeAsync({ txCode: ATTACKER_TX_CODE }, () =>
      requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_PRE_AUTH_REQUEST),
    );

    // `calls` が空でも `URLSearchParams` を引けないため、送信が起きたことを先に固定する
    // （空振りだと「載せない」ではなく「そもそも送っていない」を検証してしまう）。
    expect(calls).toHaveLength(1);
    expect(calls[0]?.body.has('tx_code')).toBe(false);
  });

  // getter は呼ばれるたびに新しい値を返せるため、汚染値との同一性比較では弾けない。
  it('継承した txCode（アクセサ汚染）も tx_code として送出しない', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await withPollutedPrototypeAccessorAsync({ txCode: () => ATTACKER_TX_CODE }, () =>
      requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_PRE_AUTH_REQUEST),
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]?.body.has('tx_code')).toBe(false);
  });

  // ポジティブコントロール。上 2 件が「汚染値を弾いた」ことを示すには、同じ汚染下で**明示指定した
  // PIN は通る**ことも示す必要がある（own 限定読みを「常に undefined を返す」実装に退行させても
  // 上 2 件は通ってしまい、過剰に弾いた場合と区別が付かない）。
  it('汚染下でも明示的に渡した txCode はそのまま tx_code に載る（正常系）', async () => {
    const calls: FetchCall[] = [];
    stubFetchOk(calls);

    await withPollutedPrototypeAsync({ txCode: ATTACKER_TX_CODE }, () =>
      requestTokenPreAuthorized(TOKEN_ENDPOINT, { ...BASE_PRE_AUTH_REQUEST, txCode: TX_CODE }),
    );

    expect(calls[0]?.body.get('tx_code')).toBe(TX_CODE);
  });
});
