/**
 * `obtainWalletUnitAttestation` の失敗経路。
 *
 * - 通信・応答の形に起因する失敗は**どちらの段でも**再試行可能な `10101` に正規化される
 *   （非 HTTPS / 署名鍵未設定 / 非 2xx / 非 JSON / challenge・nonce 欠落 / JWT 欠落 /
 *   ネットワーク / abort / 平文リダイレクト）
 * - 取得できた JWT の中身の失敗は包み直さず伝播する（署名不正は `10102`、期限切れは `10103`）
 * - 前提（`providerJwk` / `nowSeconds` / `signer`）が揃わない呼び出しは**通信を 1 回も起こさない**
 *
 * 正常系は `obtain.test.ts`。ネットワークは `fetchImpl` の注入のみで再現する。
 */

import { describe, expect, test } from 'bun:test';
import { obtainWalletUnitAttestation } from '../obtain.js';
import {
  CHALLENGE,
  CHALLENGE_URL,
  codeOf,
  ENDPOINT,
  ISSUE_URL,
  jsonResponse,
  NONCE,
  NOW,
  obtainOptions,
  PROVIDER_JWK,
  PROVIDER_KEY,
  type StubFetch,
  stubFetch,
  stubTwoStage,
} from './obtain-fixtures.js';
import { makeWuaJwt, OTHER_PRIVATE_KEY, wscdSigner } from './wua-fixtures.js';

/** 応答の最終 URL（リダイレクト後）を差し替える。 */
function withFinalUrl(response: Response, url: string): Response {
  Object.defineProperty(response, 'url', { value: url });
  return response;
}

/** 指定した段だけ差し替え、もう一方は正常応答を返すスタブ。 */
function stubStage(target: string, respond: () => Response | Promise<Response>): StubFetch {
  return stubFetch((url) => {
    if (url === target) {
      return respond();
    }
    return url === CHALLENGE_URL
      ? jsonResponse({ challenge: CHALLENGE, nonce: NONCE })
      : jsonResponse({ wallet_attestation: makeWuaJwt(PROVIDER_KEY) });
  });
}

/** 対象の段を差し替えたときのエラーコードを取る。 */
async function codeWhenStageFails(
  target: string,
  respond: () => Response | Promise<Response>,
): Promise<{ code: string; stub: StubFetch }> {
  const stub = stubStage(target, respond);
  const code = await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stub)));
  return { code, stub };
}

describe('obtainWalletUnitAttestation: 通信の前に閉じる失敗', () => {
  test('非 HTTPS の providerEndpoint は 10101 で、通信を 1 回も起こさない', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));

    const code = await codeOf(() =>
      obtainWalletUnitAttestation('http://wallet-provider.example.eu/wua', obtainOptions(stub)),
    );

    expect(code).toBe('10101');
    expect(stub.requests).toEqual([]);
  });

  test('signer を渡さない呼び出しは Proof を作れず 10101（通信も起こさない）', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));
    const options = {
      providerJwk: PROVIDER_JWK,
      nowSeconds: NOW,
      fetchImpl: stub.fetchImpl,
    } as unknown as Parameters<typeof obtainWalletUnitAttestation>[1];

    expect(await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options))).toBe('10101');
    expect(stub.requests).toEqual([]);
  });

  test('sign を持たない signer は 10101（通信も起こさない）', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));
    const options = obtainOptions(stub, {
      signer: { alg: 'ES256', publicKeyJwk: PROVIDER_JWK } as unknown as ReturnType<
        typeof wscdSigner
      >,
    });

    expect(await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options))).toBe('10101');
    expect(stub.requests).toEqual([]);
  });

  test('providerJwk を渡さない呼び出しは検証を省略せず 10102（通信も起こさない）', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));
    const options = {
      signer: wscdSigner(),
      nowSeconds: NOW,
      fetchImpl: stub.fetchImpl,
    } as unknown as Parameters<typeof obtainWalletUnitAttestation>[1];

    expect(await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options))).toBe('10102');
    expect(stub.requests).toEqual([]);
  });

  test('nowSeconds が数値でない呼び出しは期限判定を素通りさせず 10102', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY));
    const options = obtainOptions(stub, { nowSeconds: 'now' as unknown as number });

    expect(await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, options))).toBe('10102');
    expect(stub.requests).toEqual([]);
  });
});

describe('obtainWalletUnitAttestation: /wua/challenge 段の失敗（10101）', () => {
  test('非 2xx 応答は 10101 で、/wua/issue へ進まない', async () => {
    const { code, stub } = await codeWhenStageFails(
      CHALLENGE_URL,
      () => new Response('', { status: 503 }),
    );

    expect(code).toBe('10101');
    expect(stub.requests.map((request) => request.url)).toEqual([CHALLENGE_URL]);
  });

  test('JSON として解析できない本文・JSON object でない本文は 10101', async () => {
    expect((await codeWhenStageFails(CHALLENGE_URL, () => new Response('not-json'))).code).toBe(
      '10101',
    );
    expect((await codeWhenStageFails(CHALLENGE_URL, () => jsonResponse([CHALLENGE]))).code).toBe(
      '10101',
    );
  });

  test('challenge / nonce の欠落・空白のみは 10101 で、/wua/issue へ進まない', async () => {
    for (const body of [
      {},
      { challenge: CHALLENGE },
      { nonce: NONCE },
      { challenge: '   ', nonce: NONCE },
      { challenge: CHALLENGE, nonce: '' },
    ]) {
      const { code, stub } = await codeWhenStageFails(CHALLENGE_URL, () => jsonResponse(body));
      expect(code).toBe('10101');
      expect(stub.requests.map((request) => request.url)).toEqual([CHALLENGE_URL]);
    }
  });

  test('ネットワークエラー・タイムアウト（abort）は 10101', async () => {
    const network = await codeWhenStageFails(CHALLENGE_URL, () =>
      Promise.reject(new TypeError('connection refused')),
    );
    // 実タイマー 10 秒を待たず、AbortSignal 発火時と同じ拒否を注入した fetch から返す。
    const aborted = await codeWhenStageFails(CHALLENGE_URL, () =>
      Promise.reject(new DOMException('The operation was aborted.', 'AbortError')),
    );

    expect([network.code, aborted.code]).toEqual(['10101', '10101']);
  });

  test('平文へのリダイレクト（最終 URL が https 以外）は 10101', async () => {
    const { code } = await codeWhenStageFails(CHALLENGE_URL, () =>
      withFinalUrl(
        jsonResponse({ challenge: CHALLENGE, nonce: NONCE }),
        'http://attacker.example/wua/challenge',
      ),
    );

    expect(code).toBe('10101');
  });
});

describe('obtainWalletUnitAttestation: /wua/issue 段の失敗（10101）', () => {
  test('非 2xx 応答・非 JSON 本文・JSON object でない本文は 10101', async () => {
    const status = await codeWhenStageFails(ISSUE_URL, () => new Response('', { status: 500 }));
    const invalidJson = await codeWhenStageFails(ISSUE_URL, () => new Response('not-json'));
    const array = await codeWhenStageFails(ISSUE_URL, () =>
      jsonResponse([makeWuaJwt(PROVIDER_KEY)]),
    );

    expect([status.code, invalidJson.code, array.code]).toEqual(['10101', '10101', '10101']);
    expect(status.stub.requests.map((request) => request.url)).toEqual([CHALLENGE_URL, ISSUE_URL]);
  });

  test('wallet_attestation の欠落・空白のみは 10101', async () => {
    for (const body of [{}, { wallet_attestation: '' }, { wallet_attestation: '   ' }]) {
      expect((await codeWhenStageFails(ISSUE_URL, () => jsonResponse(body))).code).toBe('10101');
    }
  });

  test('ネットワークエラー・平文へのリダイレクトは 10101', async () => {
    const network = await codeWhenStageFails(ISSUE_URL, () =>
      Promise.reject(new TypeError('connection refused')),
    );
    const redirect = await codeWhenStageFails(ISSUE_URL, () =>
      withFinalUrl(
        jsonResponse({ wallet_attestation: makeWuaJwt(PROVIDER_KEY) }),
        'http://attacker.example/wua/issue',
      ),
    );

    expect([network.code, redirect.code]).toEqual(['10101', '10101']);
  });
});

describe('obtainWalletUnitAttestation: 取得できた JWT の中身の失敗（10102 / 10103）', () => {
  test('別の鍵で署名された WUA は 10102（10101 へ包み直さない）', async () => {
    const stub = stubTwoStage(makeWuaJwt(OTHER_PRIVATE_KEY));

    expect(await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stub)))).toBe(
      '10102',
    );
  });

  test('期限切れの WUA は 10103（10101 へ包み直さない）', async () => {
    const stub = stubTwoStage(makeWuaJwt(PROVIDER_KEY, { iat: NOW - 7_200, exp: NOW - 1 }));

    expect(await codeOf(() => obtainWalletUnitAttestation(ENDPOINT, obtainOptions(stub)))).toBe(
      '10103',
    );
  });
});
