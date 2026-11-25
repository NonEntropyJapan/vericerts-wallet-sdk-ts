/**
 * Token 応答メンバの `Object.prototype` 汚染耐性。
 *
 * `parseTokenResponse`（`oid4vci-token-http.ts`）は `access_token` / `token_type` /
 * `expires_in` / `c_nonce` / `c_nonce_expires_in` を鎖読みしていた。鎖読みだと
 * AS が `{}` を返しただけでも `Object.prototype.access_token` の汚染値が「AS が払い出した
 * access_token」として採用され、以降の Credential Request が攻撃者のトークンと c_nonce で
 * 走る（fail-open）。欠落した応答は欠落として 8010 へ倒す（fail-closed）。
 *
 * 検証は 2 段構えにする。`postTokenRequest` 経由の本文は `parseJsonWithoutPrototype` で
 * `null` プロトタイプ化されるため、**公開経路からは鎖読みの欠陥を観測できない**（この経路の
 * テストはパース境界が外れていないことの固定にはなるが、own 限定読み自体は覆わない）。
 * own 限定読みが唯一の防御線になるのはパース境界を通らない本文であり、そちらは
 * `parseTokenResponse` を直接呼んで固定する。
 *
 * `oid4vci-token.pollution.test.ts` は**要求側**の `txCode`を扱う別関心なので
 * 分けている（`oid4vci-par.pollution.test.ts` と同じ切り方）。
 *
 * 公開経路側は汚染下で `await` するため `withPollutedPrototype*Async` を使う（同期版は `fn` が
 * 返した Promise の解決前に汚染を戻すため、検証したい経路が汚染下で走らずトートロジーになる）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import { requestTokenPreAuthorized } from '../../token/oid4vci-token.js';
import { parseTokenResponse } from '../../token/oid4vci-token-http.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

/** AS が返す正常な Token 応答。 */
const VALID_TOKEN_BODY = {
  access_token: 'eyJhbGci.access.token',
  token_type: 'Bearer',
  expires_in: 3600,
  c_nonce: 'tZignsnFbp',
  c_nonce_expires_in: 86400,
} as const;

/** 攻撃者が `Object.prototype` に仕込む応答メンバ（正当な値と一目で区別できる形にする）。 */
const ATTACKER_TOKEN_BODY = {
  access_token: 'attacker.access.token',
  token_type: 'Bearer',
  expires_in: 3600,
  c_nonce: 'attacker-c-nonce',
  c_nonce_expires_in: 86400,
} as const;

/** 同じ汚染値をアクセサ形式でも仕込む（2 形式で値がずれないよう 1 か所から導出する）。 */
const ATTACKER_TOKEN_GETTERS: Record<string, () => unknown> = Object.fromEntries(
  Object.entries(ATTACKER_TOKEN_BODY).map(([key, value]) => [key, () => value]),
);

/** 任意フィールドを何も指定しない最小の pre-authorized_code Token Request。 */
const BASE_PRE_AUTH_REQUEST = { preAuthorizedCode: 'pre-auth-code-123' } as const;

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** `body` を HTTP 200 で返すグローバル fetch スタブ。 */
function stubFetchOk(body: unknown): void {
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

describe('parseTokenResponse: パース境界を通らない応答の汚染耐性', () => {
  // `postTokenRequest` 経由の本文は `parseJsonWithoutPrototype` で `null` プロトタイプ化される
  // ため、鎖読みの欠陥はその経路からは観測できない。own 限定読みが**唯一の防御線**になるのは
  // パース境界を通らない本文（呼び出し側が組み立てたオブジェクト）が渡る場合であり、
  // ここではそれを直接渡して固定する（`parse-json.ts` が多層防御として残せと明記する層）。
  it('汚染された応答メンバ（データ汚染）を空の応答の代わりに採用しない', () => {
    withPollutedPrototype(ATTACKER_TOKEN_BODY, () => {
      // 前提: 鎖読みなら汚染値が見える本文であること（見えないならテストがトートロジーになる）。
      expect(({} as Record<string, unknown>).access_token).toBe(ATTACKER_TOKEN_BODY.access_token);

      expect(() => parseTokenResponse({})).toThrow(
        expect.objectContaining({ code: ErrorCodes.TOKEN_REQUEST_FAILED }),
      );
    });
  });

  // getter は呼ばれるたびに値を返せるため、汚染値との同一性比較では弾けない。
  it('アクセサ汚染でも空の応答を 8010 に倒す', () => {
    withPollutedPrototypeAccessor(ATTACKER_TOKEN_GETTERS, () => {
      expect(() => parseTokenResponse({})).toThrow(
        expect.objectContaining({ code: ErrorCodes.TOKEN_REQUEST_FAILED }),
      );
    });
  });

  // ポジティブコントロール。own 限定読みを「常に undefined を返す」実装に退行させても上 2 件は
  // 通ってしまうため、同じ汚染下で own プロパティが従来どおり採用されることも固定する。
  it('汚染下でも own プロパティとして持つ応答メンバは採用する（正常系）', () => {
    const result = withPollutedPrototype(ATTACKER_TOKEN_BODY, () =>
      parseTokenResponse({ ...VALID_TOKEN_BODY }),
    );

    expect(result.accessToken).toBe(VALID_TOKEN_BODY.access_token);
    expect(result.cNonce).toBe(VALID_TOKEN_BODY.c_nonce);
  });
});

describe('requestTokenPreAuthorized: Token 応答の汚染耐性', () => {
  it('汚染された応答メンバ（データ汚染）を空の応答の代わりに採用しない', async () => {
    stubFetchOk({});

    await withPollutedPrototypeAsync(ATTACKER_TOKEN_BODY, async () => {
      await expect(
        requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_PRE_AUTH_REQUEST),
      ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    });
  });

  // getter は呼ばれるたびに値を返せるため、汚染値との同一性比較では弾けない。
  it('アクセサ汚染でも空の応答を 8010 に倒す', async () => {
    stubFetchOk({});

    await withPollutedPrototypeAccessorAsync(ATTACKER_TOKEN_GETTERS, async () => {
      await expect(
        requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_PRE_AUTH_REQUEST),
      ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
    });
  });

  // ポジティブコントロール。own 限定読みを「常に undefined を返す」実装に退行させても上 2 件は
  // 通ってしまうため、同じ汚染下で正常応答がそのまま採用されることも固定する。
  it('汚染下でも AS が実際に返した access_token / c_nonce を返す（正常系）', async () => {
    stubFetchOk(VALID_TOKEN_BODY);

    const result = await withPollutedPrototypeAsync(ATTACKER_TOKEN_BODY, () =>
      requestTokenPreAuthorized(TOKEN_ENDPOINT, BASE_PRE_AUTH_REQUEST),
    );

    expect(result.accessToken).toBe(VALID_TOKEN_BODY.access_token);
    expect(result.cNonce).toBe(VALID_TOKEN_BODY.c_nonce);
    expect(result.expiresIn).toBe(VALID_TOKEN_BODY.expires_in);
  });
});
