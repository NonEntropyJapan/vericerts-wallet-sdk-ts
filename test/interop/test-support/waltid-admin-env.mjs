// test/interop/test-support/waltid-admin-env.mjs
//
// walt.id 管理 API のベース URL（`WALTID_*_ADMIN_BASE_URL`）まわりのテスト用ヘルパ。
// ドライバは URL の既定値を持たず呼び出し時に env を読むため、実 `create*` / `poll*` を通すテストは
// env を明示する必要がある。テストごとに保存・復元し、他ファイルへ漏らさない（漏れると
// 「未設定なら throw」の検証が env の残り物で通ってしまう）。
// 4 本のドライバ（JWT-VC / SD-JWT × issuer / verifier）で同じ検証を繰り返さないよう、ケース表から
// テストを生成する。`__tests__/` の行数を増やさないため、ここ（`__tests__/` の外）に置く。
//
// 実行には Bun が必要（`bun:test` を使う）。

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';

export const ISSUER_ENV = 'WALTID_ISSUER_ADMIN_BASE_URL';
export const VERIFIER_ENV = 'WALTID_VERIFIER_ADMIN_BASE_URL';
const TEST_URLS = {
  [ISSUER_ENV]: 'http://waltid-issuer.test:7002',
  [VERIFIER_ENV]: 'http://waltid-verifier.test:7003',
};

/** `value` が `undefined` なら env を削除、それ以外はその値で上書きする。 */
function setEnv(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

/** 各テストの前に issuer / verifier の URL を設定し、後で元の値へ戻す。 */
export function useWaltidAdminEnv() {
  let saved;
  beforeEach(() => {
    saved = Object.fromEntries(Object.keys(TEST_URLS).map((name) => [name, process.env[name]]));
    for (const [name, url] of Object.entries(TEST_URLS)) setEnv(name, url);
  });
  afterEach(() => {
    for (const [name, value] of Object.entries(saved)) setEnv(name, value);
  });
}

/** 「未設定」「空文字」「空白のみ」— いずれも未指定として拒否されるべき値。 */
const MISSING_ENV_VALUES = [undefined, '', '   '];

/**
 * ドライバ関数ごとに「env の URL へ送る」「未設定・空・空白なら、どこにも送らず明示的に投げる」を検証する。
 * `useWaltidAdminEnv()` を呼んだファイルから使う。
 *
 * @param {Array<{ name: string, env: string, body: string | object | Array<string | object>, call: (fetchImpl: Function) => Promise<unknown> }>} cases
 *   `body` は `fetchImpl` が返すレスポンス本文。**配列なら呼び出し順の応答列**として扱い、尽きたら
 *   投げる（`createSdJwtIssuerOffer` のように 1 回の呼び出しで複数回引くドライバ用）。
 *   `call` はドライバ関数を呼ぶ。
 */
export function describeAdminBaseUrlRequired(cases) {
  /** 呼ばれた URL を記録する `fetchImpl` スタブ。 */
  const stub = (body) => {
    const urls = [];
    const fetchImpl = async (url) => {
      urls.push(url);
      // 配列が尽きたら末尾を繰り返さず投げる。繰り返すと、ドライバが想定より多く引くように
      // なった退行（呼び出し回数のズレ）を黙って通してしまう。
      const current = Array.isArray(body) ? body[urls.length - 1] : body;
      if (current === undefined) {
        throw new Error(
          `waltid-admin-env: 応答列が尽きた（${urls.length} 回目: ${url}）。` +
            'ドライバの呼び出し回数が変わったら `body` の配列も合わせる',
        );
      }
      return {
        ok: true,
        status: 200,
        text: async () => (typeof current === 'string' ? current : JSON.stringify(current)),
      };
    };
    return { urls, fetchImpl };
  };

  describe('管理 API のベース URL は env 必須（既定の localhost:8093 / 8094 を持たない）', () => {
    for (const { name, env, body, call } of cases) {
      it(`${name} は ${env} の値へ送る`, async () => {
        const { urls, fetchImpl } = stub(body);
        await call(fetchImpl);
        expect(urls[0]?.startsWith(`${TEST_URLS[env]}/`)).toBe(true);
      });

      for (const value of MISSING_ENV_VALUES) {
        it(`${name} は ${env} が ${JSON.stringify(value) ?? '未設定'} なら、どこにも送らず明示的に投げる`, async () => {
          setEnv(env, value);
          const { urls, fetchImpl } = stub(body);
          await expect(call(fetchImpl)).rejects.toThrow(env);
          expect(urls).toEqual([]);
        });
      }
    }
  });
}
