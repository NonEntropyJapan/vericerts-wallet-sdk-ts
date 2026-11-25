/**
 * `requestCredential`（OID4VCI Credential Endpoint）の `fetchImpl` DI に対する
 * `Object.prototype` 汚染耐性。
 *
 * `requestCredential` は `const { …, fetchImpl } = options;` の**分割代入＝プロトタイプ鎖読み**で
 * DI を取り出し、さらに `doFetch(…)` と**裸で**呼んでいた。この 2 つはそれぞれ逆向きの事故になる。
 *
 * - 鎖読み: `fetchImpl` を**省略した**正当な呼び出しが `Object.prototype.fetchImpl` の汚染値へ
 *   委譲される。Credential Request の内容（access_token を載せた `Authorization` ヘッダを含む）が
 *   攻撃者へ渡り、かつ応答＝**受領する VC を攻撃者が選べる**。
 * - own 限定にしすぎる逆方向: `class Deps { async fetchImpl(…) {…} }` と prototype メソッドで
 *   注入した正当なクラスベース DI が「未指定」と判定され、証明書ピンニング付き `fetch` が
 *   無言でグローバル `fetch` に差し替わる。
 * - 裸呼び出し: 上記クラスベース DI の `this` 参照が壊れ、`TypeError` が
 *   `ISSUER_COMMUNICATION_FAILED`(3004) に化ける。
 *
 * この 3 方向すべてを固定するため、汚染下・クラス DI 双方のテストを置く。汚染下で `await` する
 * 経路なので `withPollutedPrototype*Async` を使う（同期版は `fn` の返す Promise の解決前に汚染を
 * 戻すため、検証したい経路が汚染下で走らずトートロジーになる）。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../errors.js';
import {
  type CredentialDefinition,
  type FetchLike,
  type RequestCredentialOptions,
  requestCredential,
} from '../../oid4vci/oid4vci.js';

const ENDPOINT = 'https://issuer.example.com/credential';
const ACCESS_TOKEN = 'access-token-xyz';
const FORMAT = 'jwt_vc_json';
const DEFINITION: CredentialDefinition = { type: ['VerifiableCredential', 'UniversityDegree'] };
const PROOF_JWT = 'eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJ9.sig';
const HONEST_VC = 'eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.honest';
const ATTACKER_VC = 'eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.attacker';
const HONEST_NONCE = 'issuer-nonce-1';
const ATTACKER_NONCE = 'attacker-nonce';
const HONEST_TRANSACTION_ID = 'tx-issuer-1';
const ATTACKER_TRANSACTION_ID = 'tx-attacker';

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * `fetchImpl` を own プロパティとして**持たない** options（DI を渡さない正当な呼び出し）。
 *
 * 既存の `opts()` ヘルパは必ず `fetchImpl` を詰めるため、汚染値へのフォールバック経路は
 * ここでしか作れない。
 */
function optionsWithoutFetchImpl(): RequestCredentialOptions {
  return {
    credentialEndpoint: ENDPOINT,
    accessToken: ACCESS_TOKEN,
    format: FORMAT,
    credentialDefinition: DEFINITION,
    proofJwt: PROOF_JWT,
  };
}

/**
 * `globalThis.fetch` を差し替えて `fn` を実行し、必ず元へ戻す。
 *
 * 「汚染された `fetchImpl` を採用しない」ことは攻撃者の fetch が呼ばれない**だけ**では示せない
 * （途中の例外で落ちても同じ観測になる）。フォールバック先のグローバル `fetch` が代わりに
 * 呼ばれたところまで確認するため、実ネットワークへ出さずに差し替える。
 */
async function withStubbedGlobalFetch<T>(stub: FetchLike, fn: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = stub as unknown as typeof globalThis.fetch;
  try {
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

describe('requestCredential: fetchImpl の Object.prototype 汚染耐性', () => {
  it('fetchImpl 未指定の呼び出しが汚染値の fetch へ委譲されない（データ汚染）', async () => {
    let attackerCalls = 0;
    const attackerFetch: FetchLike = async () => {
      attackerCalls += 1;
      return jsonResponse({ credential: ATTACKER_VC });
    };
    let globalCalls = 0;
    const globalStub: FetchLike = async () => {
      globalCalls += 1;
      return jsonResponse({ credential: HONEST_VC });
    };

    const result = await withPollutedPrototypeAsync({ fetchImpl: attackerFetch }, async () =>
      withStubbedGlobalFetch(globalStub, async () => requestCredential(optionsWithoutFetchImpl())),
    );

    expect(attackerCalls).toBe(0);
    expect(globalCalls).toBe(1);
    expect(result.status).toBe('issued');
    // 受領した VC が攻撃者の選んだものに入れ替わっていないこと。
    expect(result).toMatchObject({ credential: HONEST_VC });
  });

  it('fetchImpl 未指定の呼び出しが汚染値の fetch へ委譲されない（アクセサ汚染）', async () => {
    let attackerCalls = 0;
    let globalCalls = 0;
    const globalStub: FetchLike = async () => {
      globalCalls += 1;
      return jsonResponse({ credential: HONEST_VC });
    };

    // getter は呼ばれるたびに新しい関数を返す。汚染値との同一性比較で弾く実装は素通りする。
    const result = await withPollutedPrototypeAccessorAsync(
      {
        fetchImpl: () => async () => {
          attackerCalls += 1;
          return jsonResponse({ credential: ATTACKER_VC });
        },
      },
      async () =>
        withStubbedGlobalFetch(globalStub, async () =>
          requestCredential(optionsWithoutFetchImpl()),
        ),
    );

    expect(attackerCalls).toBe(0);
    expect(globalCalls).toBe(1);
    expect(result).toMatchObject({ credential: HONEST_VC });
  });

  it('明示的に渡した fetchImpl は従来どおり使われる（非退行）', async () => {
    let calls = 0;
    const injected: FetchLike = async () => {
      calls += 1;
      return jsonResponse({ credential: HONEST_VC });
    };
    const result = await requestCredential({ ...optionsWithoutFetchImpl(), fetchImpl: injected });
    expect(calls).toBe(1);
    expect(result).toMatchObject({ credential: HONEST_VC });
  });

  /**
   * `fetchImpl` を prototype メソッドで実装したクラスベース DI（`own-property.ts` が正当と定める形）。
   *
   * `fetchImpl` は own プロパティに存在しないため、own 限定で読む実装ではグローバル `fetch` に
   * 差し替わる。さらに実装が `this` を参照するため、裸呼び出しでは `TypeError` になる。
   */
  it('prototype メソッドで注入したクラスベース DI が this 込みで使われる', async () => {
    class CredentialRequestDeps implements RequestCredentialOptions {
      readonly credentialEndpoint = ENDPOINT;
      readonly accessToken = ACCESS_TOKEN;
      readonly format = FORMAT;
      readonly credentialDefinition = DEFINITION;
      readonly proofJwt = PROOF_JWT;
      /** `this` 経由でしか読めない状態。裸呼び出しだとここで TypeError になる。 */
      readonly pinnedCredential = HONEST_VC;
      calls = 0;

      async fetchImpl(_url: string): Promise<Response> {
        this.calls += 1;
        return jsonResponse({ credential: this.pinnedCredential });
      }
    }

    const deps = new CredentialRequestDeps();
    // prototype メソッドであること（own 限定では読めない形）を明示的に固定する。
    expect(Object.hasOwn(deps, 'fetchImpl')).toBe(false);

    let globalCalls = 0;
    const result = await withStubbedGlobalFetch(
      async () => {
        globalCalls += 1;
        return jsonResponse({ credential: ATTACKER_VC });
      },
      async () => requestCredential(deps),
    );

    expect(deps.calls).toBe(1);
    expect(globalCalls).toBe(0);
    expect(result).toMatchObject({ credential: HONEST_VC });
  });
});

/**
 * Credential 応答 JSON（`parseCredentialResponse`）の汚染耐性。
 *
 * `JSON.parse` の結果は `Object.prototype` を継承するため、応答メンバを鎖読みすると
 * **Issuer が `{}` を返しただけで**汚染値が「Issuer が発行した VC」として採用される。
 * `typeof … === 'string'` のガードは汚染値が文字列であれば素通りするので防げない。
 *
 * 3 メンバはそれぞれ別の実害になるため、テストも 1 メンバずつ単独で汚染する
 * （まとめて汚染すると 1 行を鎖読みに戻しても別の行が先に落ちてしまい、
 * 「この行を戻すと落ちる」という mutation check が成立しない）。
 */
describe('requestCredential: Credential 応答 JSON の Object.prototype 汚染耐性', () => {
  /** 常に `body` を 200 で返す `fetchImpl`（Issuer の応答を固定する）。 */
  function respondWith(body: unknown): FetchLike {
    return async () => jsonResponse(body);
  }

  it('空応答に対し汚染された credential を受領 VC として採用しない（データ汚染）', async () => {
    await withPollutedPrototypeAsync({ credential: ATTACKER_VC }, async () => {
      await expect(
        requestCredential({ ...optionsWithoutFetchImpl(), fetchImpl: respondWith({}) }),
      ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    });
  });

  it('空応答に対し汚染された credential を受領 VC として採用しない（アクセサ汚染）', async () => {
    await withPollutedPrototypeAccessorAsync({ credential: () => ATTACKER_VC }, async () => {
      await expect(
        requestCredential({ ...optionsWithoutFetchImpl(), fetchImpl: respondWith({}) }),
      ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    });
  });

  it('空応答を汚染された transaction_id で遅延発行に化けさせない（データ汚染）', async () => {
    await withPollutedPrototypeAsync({ transaction_id: ATTACKER_TRANSACTION_ID }, async () => {
      await expect(
        requestCredential({ ...optionsWithoutFetchImpl(), fetchImpl: respondWith({}) }),
      ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
    });
  });

  it('空応答を汚染された transaction_id で遅延発行に化けさせない（アクセサ汚染）', async () => {
    await withPollutedPrototypeAccessorAsync(
      { transaction_id: () => ATTACKER_TRANSACTION_ID },
      async () => {
        await expect(
          requestCredential({ ...optionsWithoutFetchImpl(), fetchImpl: respondWith({}) }),
        ).rejects.toMatchObject({ code: ErrorCodes.CREDENTIAL_REQUEST_FAILED });
      },
    );
  });

  // c_nonce は欠落が正常なので、応答自体は成功させたうえで汚染値が cNonce に載らないことを見る
  // （鎖読みだと後続の JWT Proof が攻撃者の選んだ nonce にバインドされる）。
  it('c_nonce を返さない応答で汚染された c_nonce を後続 Proof 用に採用しない（データ汚染）', async () => {
    const result = await withPollutedPrototypeAsync(
      { c_nonce: ATTACKER_NONCE },
      async () =>
        await requestCredential({
          ...optionsWithoutFetchImpl(),
          fetchImpl: respondWith({ credential: HONEST_VC }),
        }),
    );
    expect(result).toMatchObject({ status: 'issued', credential: HONEST_VC });
    expect(result.cNonce).toBeUndefined();
  });

  it('c_nonce を返さない応答で汚染された c_nonce を後続 Proof 用に採用しない（アクセサ汚染）', async () => {
    const result = await withPollutedPrototypeAccessorAsync(
      { c_nonce: () => ATTACKER_NONCE },
      async () =>
        await requestCredential({
          ...optionsWithoutFetchImpl(),
          fetchImpl: respondWith({ credential: HONEST_VC }),
        }),
    );
    expect(result.cNonce).toBeUndefined();
  });

  it('汚染下でも Issuer が実際に返した credential / c_nonce をそのまま返す（非退行）', async () => {
    const result = await withPollutedPrototypeAsync(
      { credential: ATTACKER_VC, transaction_id: ATTACKER_TRANSACTION_ID, c_nonce: ATTACKER_NONCE },
      async () =>
        await requestCredential({
          ...optionsWithoutFetchImpl(),
          fetchImpl: respondWith({ credential: HONEST_VC, c_nonce: HONEST_NONCE }),
        }),
    );
    expect(result).toMatchObject({ status: 'issued', credential: HONEST_VC });
    expect(result.cNonce).toBe(HONEST_NONCE);
  });

  it('汚染下でも Issuer が実際に返した transaction_id で遅延発行になる（非退行）', async () => {
    const result = await withPollutedPrototypeAsync(
      { credential: ATTACKER_VC, transaction_id: ATTACKER_TRANSACTION_ID },
      async () =>
        await requestCredential({
          ...optionsWithoutFetchImpl(),
          fetchImpl: respondWith({ transaction_id: HONEST_TRANSACTION_ID }),
        }),
    );
    expect(result).toMatchObject({ status: 'deferred', transactionId: HONEST_TRANSACTION_ID });
  });
});
