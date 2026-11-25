/**
 * `bindInjectedFetch`（`internal/http/bind-fetch.ts`）の規律の回帰テスト（解決規則の SoT だけが
 * `internal/fetch-di.ts` の `resolveInjectedFetch` にある）。
 *
 * シームを**関数値のまま下流へ配る**入口（`wallet/factory.ts` / EUDI 受領・提示など）のヘルパーで、
 * `internal/fetch-di.ts` の `resolveInjectedFetch` と同じ規則に `bind` を足したものである。押さえる契約は 4 つ。
 *
 * 1. `this` 参照つきの prototype メソッド DI が、取り出し元をレシーバとして束ねられる。
 * 2. **グローバル `fetch` そのものを明示注入した場合は束ねない** —— 束ねるとブラウザの
 *    WebIDL ブランドチェックで `Illegal invocation` になり、呼び出し側の catch が幻の通信障害へ
 *    正規化する（Bun / Node は `this` を検査しないので、実行結果ではなくレシーバ束縛の有無を
 *    直接観測する）。
 * 3. `Object.prototype` 由来の値は「注入された」と見なさない（汚染値へ取得を委譲させない）。
 * 4. 束ねる対象は**渡されたオブジェクトそのもの**である。同じ `Deps` でも、インスタンスをそのまま
 *    渡せば prototype メソッドが鎖上で見つかって `this` ごと束ねられ、スプレッドでコピーした
 *    リテラルからは見つからない。この依存引数の公開契約では元のインスタンスをそのまま渡す。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { bindInjectedFetch } from '../bind-fetch.js';

const POLLUTED_KEY = 'eudiFetchImpl';

afterEach(() => {
  delete (Object.prototype as Record<string, unknown>)[POLLUTED_KEY];
});

describe('bindInjectedFetch', () => {
  it('this 参照つきの prototype メソッド DI を取り出し元へ束ねる', async () => {
    class Deps {
      readonly marker = 'instance-state';
      async eudiFetchImpl(): Promise<Response> {
        return new Response(this.marker, { status: 200 });
      }
    }
    const deps = new Deps();

    const bound = bindInjectedFetch(deps, POLLUTED_KEY);
    // 裸の関数値として（レシーバ無しで）呼んでも `this` が生きていること。
    const response = await (bound as (...args: never[]) => Promise<Response>)();

    expect(await response.text()).toBe('instance-state');
  });

  it('グローバル fetch そのものの明示注入には束ねない', () => {
    const bound = bindInjectedFetch({ [POLLUTED_KEY]: globalThis.fetch }, POLLUTED_KEY);

    // `bind` すると別の関数オブジェクトになるので、同一参照であることが「束ねていない」の印。
    expect(bound).toBe(globalThis.fetch as unknown as typeof bound);
  });

  it('Object.prototype 由来の値は注入と見なさない（undefined を返す）', () => {
    (Object.prototype as Record<string, unknown>)[POLLUTED_KEY] = () =>
      Promise.resolve(new Response('attacker'));

    expect(bindInjectedFetch({}, POLLUTED_KEY)).toBeUndefined();
    expect(bindInjectedFetch({ [POLLUTED_KEY]: undefined }, POLLUTED_KEY)).toBeUndefined();
  });

  it('同じ Deps でも、インスタンスなら束ねられコピーしたリテラルからは見つからない', async () => {
    class Deps {
      readonly agent = { fetch: async () => new Response('instance-state', { status: 200 }) };
      async eudiFetchImpl(): Promise<Response> {
        return this.agent.fetch();
      }
    }
    const deps = new Deps();

    // インスタンスをレシーバのまま渡せば、prototype 上のメソッドが見つかり `this` も解決する。
    const bound = bindInjectedFetch(deps, POLLUTED_KEY);
    expect(bound).toBeDefined();
    const response = await (bound as (...args: never[]) => Promise<Response>)();
    expect(await response.text()).toBe('instance-state');

    // 同じ `deps` でも、スプレッドは own enumerable プロパティしか写さないので `Deps.prototype` 上の
    // メソッドが落ち、「シーム未指定」に見える（無言でグローバル fetch へ落ちる形）。
    expect(bindInjectedFetch({ ...deps }, POLLUTED_KEY)).toBeUndefined();
  });

  it('関数でない値（未指定・null・文字列）は undefined を返す', () => {
    expect(bindInjectedFetch({}, POLLUTED_KEY)).toBeUndefined();
    expect(bindInjectedFetch({ [POLLUTED_KEY]: null }, POLLUTED_KEY)).toBeUndefined();
    expect(bindInjectedFetch({ [POLLUTED_KEY]: 'https://attacker.example' }, POLLUTED_KEY)).toBe(
      undefined,
    );
  });
});
