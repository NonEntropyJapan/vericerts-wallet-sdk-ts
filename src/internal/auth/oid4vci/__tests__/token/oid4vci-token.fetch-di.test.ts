/**
 * Token Request の `fetchImpl` DI シームのテスト。
 *
 * EUDI の受領フロー（`internal/eudi/issuance`）は実ネットワークを使わずに検証する必要があり、
 * リポジトリの方針（`credential/vc/credential-schema/__tests__/fixtures.ts`）は
 * 「グローバル `fetch` は差し替えず、実装が公開している DI シームのみを使う」と定めている。
 * そのため Token Request にも Credential Endpoint 経路（`RequestCredentialOptions.fetchImpl`）/
 * PAR 経路（`PARRequest.fetchImpl`）と同じシームを追加した。
 *
 * ここで検証する不変条件は PAR 経路（`oid4vci-par.test.ts` / `oid4vci-fetch-di.test.ts`）と同じ:
 * 注入した実装が実際に使われること・`Object.prototype` 由来の値は採用しないこと・関数でない値は
 * 未注入として扱うこと・取り出し元をレシーバとして呼ぶこと。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FetchLike } from '../../oid4vci.js';
import {
  requestTokenAuthorizationCode,
  requestTokenPreAuthorized,
} from '../../token/oid4vci-token.js';

const TOKEN_ENDPOINT = 'https://issuer.example.com/token';

/** AS が返す正常な Token 応答。 */
const VALID_TOKEN_BODY = {
  access_token: 'eyJhbGci.access.token',
  token_type: 'Bearer',
  expires_in: 3600,
  c_nonce: 'tZignsnFbp',
  c_nonce_expires_in: 86400,
} as const;

/** 呼び出しを記録しつつ正常応答を返すスタブ。 */
function createStub(): { fetchImpl: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: FetchLike = (url, _init) => {
    calls.push(url);
    return Promise.resolve(
      new Response(JSON.stringify(VALID_TOKEN_BODY), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  };
  return { fetchImpl, calls };
}

describe('requestTokenPreAuthorized / fetchImpl DI', () => {
  it('注入した fetchImpl を使って Token Request を送る', async () => {
    const { fetchImpl, calls } = createStub();
    const token = await requestTokenPreAuthorized(TOKEN_ENDPOINT, {
      preAuthorizedCode: 'pre-auth-code',
      fetchImpl,
    });
    expect(calls).toEqual([TOKEN_ENDPOINT]);
    expect(token.accessToken).toBe(VALID_TOKEN_BODY.access_token);
    expect(token.cNonce).toBe(VALID_TOKEN_BODY.c_nonce);
  });

  it('取り出し元をレシーバとして呼ぶ（this 参照つき実装が壊れない）', async () => {
    const request = {
      preAuthorizedCode: 'pre-auth-code',
      marker: 'self',
      seen: [] as string[],
      fetchImpl(this: { marker: string; seen: string[] }, _url: string): Promise<Response> {
        this.seen.push(this.marker);
        return Promise.resolve(
          new Response(JSON.stringify(VALID_TOKEN_BODY), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        );
      },
    };
    await requestTokenPreAuthorized(TOKEN_ENDPOINT, request as never);
    expect(request.seen).toEqual(['self']);
  });

  it('Object.prototype 由来の fetchImpl は採用せずグローバル fetch へ倒す', async () => {
    const attacker = { called: false };
    const polluted: FetchLike = (_url, _init) => {
      attacker.called = true;
      return Promise.resolve(new Response('{}', { status: 200 }));
    };
    // 本ケースの検証対象は「未注入時のフォールバック先」そのものなので、例外的にグローバル
    // `fetch` を差し替えて観測する（実ネットワークへ出さないため。同ディレクトリの既存 token
    // テストと同じ形で、`finally` で必ず復元する）。
    const originalFetch = globalThis.fetch;
    let globalCalled = false;
    globalThis.fetch = (() => {
      globalCalled = true;
      return Promise.resolve(
        new Response(JSON.stringify(VALID_TOKEN_BODY), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }) as unknown as typeof fetch;
    try {
      await withPollutedPrototypeAsync({ fetchImpl: polluted }, async () => {
        await requestTokenPreAuthorized(TOKEN_ENDPOINT, { preAuthorizedCode: 'pre-auth-code' });
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(attacker.called).toBe(false);
    expect(globalCalled).toBe(true);
  });
});

describe('requestTokenAuthorizationCode / fetchImpl DI', () => {
  it('注入した fetchImpl を使って Token Request を送る', async () => {
    const { fetchImpl, calls } = createStub();
    const token = await requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
      code: 'authz-code',
      codeVerifier: 'verifier',
      fetchImpl,
    });
    expect(calls).toEqual([TOKEN_ENDPOINT]);
    expect(token.accessToken).toBe(VALID_TOKEN_BODY.access_token);
  });

  it('関数でない fetchImpl は未注入として扱い、生の TypeError を漏らさない', async () => {
    // 未注入扱いでグローバル `fetch` へ倒れることを、到達不能な応答を返す差し替えで観測する。
    // 非関数値をそのまま呼ぶ実装だと生の `TypeError` が漏れ、8010 への正規化が壊れる。
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.reject(new TypeError('fetch failed'))) as unknown as typeof fetch;
    try {
      await requestTokenAuthorizationCode(TOKEN_ENDPOINT, {
        code: 'authz-code',
        codeVerifier: 'verifier',
        fetchImpl: 'not-a-function' as never,
      });
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
