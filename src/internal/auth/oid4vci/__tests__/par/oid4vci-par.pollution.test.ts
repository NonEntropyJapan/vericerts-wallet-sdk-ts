/**
 * `PARRequest` の任意フィールドに対する `Object.prototype` 汚染耐性。
 *
 * `pushAuthorizationRequest` が `scope` / `authorization_details` / `client_assertion` /
 * `client_assertion_type` / `fetchImpl` をプロトタイプ鎖で読んでいると、それらを**省略した**
 * 正当な push でも汚染値が採用され、攻撃者のパラメータが AS へ送られる（`fetchImpl` に至っては
 * client_assertion を含む本文ごと攻撃者の fetch へ渡る）。純データは own 限定、`fetchImpl` は
 * `Object.prototype` 由来のみ除外（`internal/fetch-di.ts`）という使い分けを固定する。
 *
 * `dpop` の同種テストは `oid4vci-par.test.ts` にある。本ファイルを分けているのは
 * 1 ファイル 300 行の上限のため。
 *
 * 汚染下で `await` する経路なので `withPollutedPrototype*Async` を使う（同期版は `fn` が返した
 * Promise の解決前に汚染を戻すため、検証したい経路が汚染下で走らずトートロジーになる）。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import type { FetchLike } from '../../oid4vci.js';
import type { PARRequest } from '../../par/index.js';
import { pushAuthorizationRequest } from '../../par/index.js';
import {
  baseRequest,
  type FetchCall,
  PAR_ENDPOINT,
  STATE,
  stubFetchOk,
  VALID_PAR_BODY,
  WALLET_ATTESTATION_ASSERTION_TYPE,
} from './par-fixtures.js';

const CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const REDIRECT_URI = 'com.example.wallet://cb';

/**
 * 攻撃者が `Object.prototype` に仕込む `client_assertion`。正当な値の共有定数
 * `WALLET_ATTESTATION_CLIENT_ASSERTION`（`<WUA>~<WUA-PoP>`）へは**移行しない**:
 * 本ファイルが固定するのは「汚染値は形式によらず一切採用されない」ことであり、正当な値と
 * 同じ定数を使うと「正当な形式だから弾かれた／通った」の取り違えが起きる。攻撃者由来だと
 * 一目で分かる値を使い、`<WUA>~<WUA-PoP>` を満たさないことを意図とする。
 */
const ATTACKER_CLIENT_ASSERTION = 'eyJ.attacker.assertion';

/**
 * `fetchImpl` を own プロパティとして持たない PAR リクエスト（DI を指定しない正当な呼び出し）。
 *
 * `baseRequest` は必ず `fetchImpl` を詰めるため、汚染値のフォールバック経路はここでしか作れない。
 */
function requestWithoutFetchImpl(): PARRequest {
  return {
    par_endpoint: PAR_ENDPOINT,
    client_id: 'wallet-client',
    code_challenge: CODE_CHALLENGE,
    redirect_uri: REDIRECT_URI,
    state: STATE,
  };
}

/**
 * `globalThis.fetch` を差し替えて `fn` を実行し、必ず元へ戻す。
 *
 * 「汚染された `fetchImpl` を採用しない」ことは、攻撃者の fetch が呼ばれない**だけ**では
 * 示せない（途中の例外で落ちても同じ観測になる）。フォールバック先のグローバル `fetch` が
 * 代わりに呼ばれたところまで確認するため、実ネットワークへ出さずに差し替える。
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

/**
 * `fetchImpl` を prototype メソッドとして実装するクラスベース DI（`own-property.ts` が正当と
 * 定める形）。実装が `this` を参照するため、取り出した関数を裸で呼ぶと `TypeError` になり
 * `ISSUER_COMMUNICATION_FAILED`(3004) へ潰れる。
 */
class ParRequestWithFetchMethod implements PARRequest {
  readonly par_endpoint = PAR_ENDPOINT;
  readonly client_id = 'wallet-client';
  readonly code_challenge = CODE_CHALLENGE;
  readonly redirect_uri = REDIRECT_URI;
  readonly state = STATE;
  /** インスタンス状態。`this` が正しく束ねられた場合だけ応答に現れる。 */
  readonly marker = 'urn:ietf:params:oauth:request_uri:instance-bound';
  /** 記録先もインスタンス状態（証明書ピンニング設定や接続プールの代役）。 */
  readonly calls: FetchCall[] = [];

  async fetchImpl(url: string, init: Parameters<FetchLike>[1]): Promise<Response> {
    this.calls.push({ url, init, body: new URLSearchParams(init.body) });
    return new Response(JSON.stringify({ request_uri: this.marker, expires_in: 60 }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

describe('PARRequest.fetchImpl の DI 解決', () => {
  it('継承した fetchImpl（データプロパティ汚染）は採用せずグローバル fetch へ倒す', async () => {
    const attackerCalls: FetchCall[] = [];
    const attackerFetch = stubFetchOk(VALID_PAR_BODY, attackerCalls);
    const globalCalls: FetchCall[] = [];

    await withStubbedGlobalFetch(stubFetchOk(VALID_PAR_BODY, globalCalls), () =>
      withPollutedPrototypeAsync({ fetchImpl: attackerFetch }, () =>
        pushAuthorizationRequest(requestWithoutFetchImpl()),
      ),
    );

    // 鎖読みだと client_assertion を含む本文ごと攻撃者の fetch へ渡る。
    expect(attackerCalls).toHaveLength(0);
    expect(globalCalls).toHaveLength(1);
  });

  it('継承した fetchImpl（アクセサ汚染）は採用せずグローバル fetch へ倒す', async () => {
    const attackerCalls: FetchCall[] = [];
    const attackerFetch = stubFetchOk(VALID_PAR_BODY, attackerCalls);
    const globalCalls: FetchCall[] = [];

    // getter は呼ばれるたびに値を返せるため、汚染値との同一性比較では弾けない。
    await withStubbedGlobalFetch(stubFetchOk(VALID_PAR_BODY, globalCalls), () =>
      withPollutedPrototypeAccessorAsync({ fetchImpl: () => attackerFetch }, () =>
        pushAuthorizationRequest(requestWithoutFetchImpl()),
      ),
    );

    expect(attackerCalls).toHaveLength(0);
    expect(globalCalls).toHaveLength(1);
  });

  it('明示的に渡した fetchImpl はそのまま使う（グローバル fetch へ倒さない）', async () => {
    const calls: FetchCall[] = [];
    const globalCalls: FetchCall[] = [];

    const res = await withStubbedGlobalFetch(stubFetchOk(VALID_PAR_BODY, globalCalls), () =>
      pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );

    expect(calls).toHaveLength(1);
    expect(globalCalls).toHaveLength(0);
    expect(res.request_uri).toBe(VALID_PAR_BODY.request_uri);
  });

  it('prototype メソッドで注入された fetchImpl を this ごと使う', async () => {
    const globalCalls: FetchCall[] = [];
    const req = new ParRequestWithFetchMethod();
    // own プロパティではない = own 限定で読むと「未指定」に見える形。
    expect(Object.hasOwn(req, 'fetchImpl')).toBe(false);

    const res = await withStubbedGlobalFetch(stubFetchOk(VALID_PAR_BODY, globalCalls), () =>
      pushAuthorizationRequest(req),
    );

    // own 限定に「強化」すると注入がグローバル fetch へ無言で差し替わり marker が現れない。
    expect(res.request_uri).toBe(req.marker);
    expect(globalCalls).toHaveLength(0);
    // レシーバを束ねずに呼ぶと `this.calls` が TypeError になり 3004 へ潰れる。
    expect(req.calls).toHaveLength(1);
    expect(req.calls[0]?.body.get('client_id')).toBe('wallet-client');
  });
});

describe('PARRequest の任意ワイヤパラメータの汚染耐性', () => {
  it('継承した scope は body に載せない', async () => {
    const calls: FetchCall[] = [];
    await withPollutedPrototypeAsync({ scope: 'AttackerScope' }, () =>
      pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );
    expect(calls[0]?.body.has('scope')).toBe(false);
  });

  it('継承した authorization_details は body に載せない', async () => {
    const calls: FetchCall[] = [];
    const attackerDetails = [{ type: 'openid_credential', credential_configuration_id: 'evil' }];
    await withPollutedPrototypeAsync({ authorization_details: attackerDetails }, () =>
      pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );
    expect(calls[0]?.body.has('authorization_details')).toBe(false);
  });

  // 鎖読みだと「assertion を指定していない」正当な push が RFC 7521 ガードに引っかかって
  // 8010 で落ちる（可用性の毀損）。汚染値はガードから見えてもいけない。
  it('継承した client_assertion は RFC 7521 ガードから見えず body にも載らない', async () => {
    const calls: FetchCall[] = [];
    const res = await withPollutedPrototypeAsync(
      { client_assertion: ATTACKER_CLIENT_ASSERTION },
      () => pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );
    expect(res.request_uri).toBe(VALID_PAR_BODY.request_uri);
    expect(calls[0]?.body.has('client_assertion')).toBe(false);
    expect(calls[0]?.body.has('client_assertion_type')).toBe(false);
  });

  it('継承した client_assertion / client_assertion_type の対はクライアント認証として送らない', async () => {
    const calls: FetchCall[] = [];
    await withPollutedPrototypeAsync(
      {
        client_assertion: ATTACKER_CLIENT_ASSERTION,
        client_assertion_type: WALLET_ATTESTATION_ASSERTION_TYPE,
      },
      () => pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );
    // 鎖読みだと攻撃者の assertion が Wallet のクライアント認証として AS へ送出される。
    expect(calls[0]?.body.has('client_assertion')).toBe(false);
    expect(calls[0]?.body.has('client_assertion_type')).toBe(false);
  });
});

describe('pushAuthorizationRequest: PAR 応答の汚染耐性', () => {
  /**
   * `JSON.parse` の結果は `Object.prototype` を継承するため、応答メンバを鎖読みすると
   * AS が `{}` を返しただけでも汚染値が「AS が払い出した request_uri」として採用される。
   * 採用された `request_uri` は `buildAuthorizationUrl` が front-channel の認可 URL に載せるので、
   * 攻撃者が認可要求そのものを差し替えられる。欠落応答は 8010 へ倒す（fail-closed）。
   */
  it('汚染された request_uri / expires_in を空の応答の代わりに採用しない', async () => {
    const calls: FetchCall[] = [];
    await withPollutedPrototypeAsync(
      {
        request_uri: 'https://attacker.example.com/hijacked',
        expires_in: 3600,
      },
      async () => {
        await expect(
          pushAuthorizationRequest(baseRequest(stubFetchOk({}, calls))),
        ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
      },
    );
  });

  /** getter 形式の汚染でも同じ（同一性比較で除外する実装は getter を素通りさせる）。 */
  it('アクセサ汚染でも空の応答を 8010 に倒す', async () => {
    const calls: FetchCall[] = [];
    await withPollutedPrototypeAccessorAsync(
      {
        request_uri: () => 'https://attacker.example.com/hijacked',
        expires_in: () => 3600,
      },
      async () => {
        await expect(
          pushAuthorizationRequest(baseRequest(stubFetchOk({}, calls))),
        ).rejects.toMatchObject({ code: ErrorCodes.TOKEN_REQUEST_FAILED });
      },
    );
  });

  /** 正常応答は汚染下でも AS が返した値をそのまま採用する（own 化の非退行）。 */
  it('汚染下でも AS が実際に返した request_uri を返す', async () => {
    const calls: FetchCall[] = [];
    const result = await withPollutedPrototypeAsync(
      { request_uri: 'https://attacker.example.com/hijacked', expires_in: 3600 },
      async () => await pushAuthorizationRequest(baseRequest(stubFetchOk(VALID_PAR_BODY, calls))),
    );
    expect(result.request_uri).toBe(VALID_PAR_BODY.request_uri);
    expect(result.expires_in).toBe(VALID_PAR_BODY.expires_in);
  });
});
