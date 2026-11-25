/**
 * `resolveInjectedFetch`（`internal/fetch-di.ts`）のレシーバ束ねの分岐。
 *
 * `fetchImpl` から取り出した関数は「取り出し元をレシーバに束ねて呼ぶ」のが原則だが、
 * **グローバル `fetch` そのもの**にレシーバを束ねてはならない。ブラウザの WebIDL
 * ブランドチェックが `this` を検査し、`Illegal invocation` の TypeError になるためである。
 * 呼び出し側の try/catch はこれを `ISSUER_COMMUNICATION_FAILED`(3004, 再試行可) へ正規化するので、
 * 呼び出し側からは**幻の通信障害**にしか見えない。
 *
 * 束ねないのは「`fetchImpl` を省略したときのフォールバック」だけでは足りない。
 * `fetchImpl: globalThis.fetch` と**素のグローバル `fetch` を明示注入**するのも正当な使い方で、
 * この経路も束ねてはならない。
 *
 * Bun / Node の `fetch` は `this` を検査しないため `Illegal invocation` はここでは再現できない。
 * そこで「レシーバが束ねられていないこと」自体を観測する: `globalThis.fetch` を**呼ばれたときの
 * `this` を記録するスタブ**に差し替え、それを `fetchImpl` として明示注入して、記録された `this` が
 * `undefined` であることを確かめる。対比として、prototype メソッドで注入したクラス DI では
 * 従来どおり `this` がインスタンスになることを同じファイルで固定する。
 */

import { describe, expect, it } from 'bun:test';
import { type FetchLike, resolveInjectedFetch } from '../../../fetch-di.js';
import { type PARRequest, pushAuthorizationRequest } from '../par/index.js';
import { PAR_ENDPOINT, STATE, VALID_PAR_BODY } from './par/par-fixtures.js';

const CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const REDIRECT_URI = 'com.example.wallet://cb';

/** AS の正常応答（RFC 9126 §2.2）。 */
function parOkResponse(): Response {
  return new Response(JSON.stringify(VALID_PAR_BODY), {
    status: 201,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * 呼ばれたときの `this` を `seen` に記録する fetch スタブ。
 *
 * アロー関数だと `this` が定義時のスコープに字句束縛され観測にならないため、必ず `function` で作る
 * （ESM は strict mode なので、レシーバ無しで呼ばれた場合の `this` は `globalThis` ではなく
 * `undefined` になる）。
 */
function recordingFetch(seen: unknown[]): FetchLike {
  return function recorded(this: unknown): Promise<Response> {
    seen.push(this);
    return Promise.resolve(parOkResponse());
  };
}

/** `globalThis.fetch` を差し替えて `fn` を実行し、必ず元へ戻す。 */
async function withStubbedGlobalFetch<T>(stub: FetchLike, fn: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = stub as unknown as typeof globalThis.fetch;
  try {
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

/** `fetchImpl` 以外の必須フィールドだけを持つ PAR リクエストの素材。 */
function baseFields(): Omit<PARRequest, 'fetchImpl'> {
  return {
    par_endpoint: PAR_ENDPOINT,
    client_id: 'wallet-client',
    code_challenge: CODE_CHALLENGE,
    redirect_uri: REDIRECT_URI,
    state: STATE,
  };
}

describe('resolveInjectedFetch: グローバル fetch にレシーバを束ねない', () => {
  it('素のグローバル fetch を fetchImpl として明示注入してもレシーバを束ねない', async () => {
    const seen: unknown[] = [];

    await withStubbedGlobalFetch(recordingFetch(seen), async () => {
      // 呼び出し側が `fetchImpl: globalThis.fetch` と素のグローバル fetch を明示注入する形。
      const req: PARRequest = {
        ...baseFields(),
        fetchImpl: globalThis.fetch as unknown as FetchLike,
      };
      expect(resolveInjectedFetch(req).receiver).toBeUndefined();
      await pushAuthorizationRequest(req);
    });

    expect(seen).toHaveLength(1);
    // 束ねていれば `this` は `req` になる = ブラウザで `Illegal invocation` になる形。
    expect(seen[0]).toBeUndefined();
  });

  it('Credential Endpoint 側の options でも素のグローバル fetch にはレシーバを束ねない', () => {
    const seen: unknown[] = [];
    return withStubbedGlobalFetch(recordingFetch(seen), async () => {
      // `resolveInjectedFetch` は PAR / Credential 両経路の共有ロジックなので、source の形に
      // 依らず同じ分岐になることを固定する。
      const options = { fetchImpl: globalThis.fetch as unknown as FetchLike };
      expect(resolveInjectedFetch(options).receiver).toBeUndefined();
    });
  });

  it('fetchImpl 未指定ならグローバル fetch をレシーバ無しで呼ぶ', async () => {
    const seen: unknown[] = [];
    await withStubbedGlobalFetch(recordingFetch(seen), async () =>
      pushAuthorizationRequest(baseFields()),
    );
    expect(seen).toEqual([undefined]);
  });

  it('prototype メソッドで注入したクラス DI には従来どおりインスタンスを束ねる', async () => {
    const seen: unknown[] = [];

    class ParRequestDeps implements PARRequest {
      readonly par_endpoint = PAR_ENDPOINT;
      readonly client_id = 'wallet-client';
      readonly code_challenge = CODE_CHALLENGE;
      readonly redirect_uri = REDIRECT_URI;
      readonly state = STATE;

      async fetchImpl(this: ParRequestDeps): Promise<Response> {
        seen.push(this);
        return parOkResponse();
      }
    }

    const deps = new ParRequestDeps();
    // own プロパティではない（own 限定では読めない）形であることを明示的に固定する。
    expect(Object.hasOwn(deps, 'fetchImpl')).toBe(false);
    expect(resolveInjectedFetch(deps).receiver).toBe(deps);

    await withStubbedGlobalFetch(recordingFetch([]), async () => pushAuthorizationRequest(deps));

    expect(seen).toHaveLength(1);
    expect(seen[0]).toBe(deps);
  });
});

/**
 * 「関数でない値はすべて未注入として扱う」規則（`internal/fetch-di.ts` の JSDoc）の回帰。
 *
 * 型のない JS からの呼び出しでのみ到達する経路なので、TypeScript 側はキャストで作る。
 * この規則が無いと `fetchImpl: '汚染された文字列'` や `fetchImpl: {}` が「注入された」と
 * 判定され、`doFetch` に関数でない値が入ったまま `doFetch.call(...)` で `TypeError` になり、
 * 呼び出し側で `ISSUER_COMMUNICATION_FAILED`(3004, 再試行可) の**幻の通信障害**へ潰れる。
 * `Object.prototype` 汚染で非関数値が生える場合も同じ経路に落ちる。
 */
describe('resolveInjectedFetch: 関数でない fetchImpl は未注入として扱う', () => {
  const nonFunctionValues: readonly (readonly [string, unknown])[] = [
    ['null', null],
    ['汚染された文字列', '汚染された文字列'],
    ['オブジェクト', {}],
  ];

  for (const [label, value] of nonFunctionValues) {
    it(`fetchImpl: ${label} はグローバル fetch へ倒しレシーバを束ねない`, () => {
      const source = { fetchImpl: value };

      const { doFetch, receiver } = resolveInjectedFetch(source);

      expect(doFetch).toBe(globalThis.fetch as unknown as FetchLike);
      expect(receiver).toBeUndefined();
    });

    it(`fetchImpl: ${label} でも PAR はグローバル fetch をレシーバ無しで呼ぶ`, async () => {
      const seen: unknown[] = [];

      await withStubbedGlobalFetch(recordingFetch(seen), async () =>
        pushAuthorizationRequest({ ...baseFields(), fetchImpl: value } as unknown as PARRequest),
      );

      expect(seen).toEqual([undefined]);
    });
  }
});
