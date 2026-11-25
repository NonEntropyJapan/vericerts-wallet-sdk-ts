/**
 * Credential Endpoint の応答**本文**読み出しがタイムアウトと例外正規化の内側にあること。
 *
 * 回帰観点:
 * - ヘッダだけ先に返して本文を送り続ける Issuer に対し、`requestCredential` が
 *   `CREDENTIAL_REQUEST_TIMEOUT_MS` で abort され `ISSUER_COMMUNICATION_FAILED`(3004) になること
 *   （`clearTimeout` が本文読了より前にあると、この待ちは無期限になる）
 * - 本文読み出し中のストリーム失敗が生の `TypeError` ではなく `VericertsError` になること
 *   （`@throws` 契約は通信失敗 3004 / 応答不正 8020 のみを約束している）
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FetchLike } from '../../../../fetch-di.js';
import { type RequestCredentialOptions, requestCredential } from '../../oid4vci.js';

const CREDENTIAL_URL = 'https://issuer.example.com/credential';

function options(fetchImpl: FetchLike): RequestCredentialOptions {
  return {
    credentialEndpoint: CREDENTIAL_URL,
    accessToken: 'access-token-value',
    format: 'dc+sd-jwt',
    credentialDefinition: { type: ['UniversityDegree'] },
    proofJwt: 'header.payload.sig',
    fetchImpl,
  };
}

/**
 * ヘッダは 200 で即座に返し、本文は 1 バイトも流さずに保持し続ける Issuer。
 *
 * 実 `fetch` は abort されると本文ストリームをエラーにするため、その挙動だけを再現する。
 */
function stallingBodyFetch(): FetchLike {
  return (_url, init) =>
    Promise.resolve(
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            init.signal.addEventListener('abort', () => {
              controller.error(new TypeError('The operation was aborted.'));
            });
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );
}

describe('requestCredential の本文読み出しタイムアウト', () => {
  test('ヘッダのみ返して本文を送り続ける Issuer はタイムアウトで 3004 になる', async () => {
    // SDK が張るタイムアウトだけを 10 ms へ短縮する（実時間で 10 秒待たないため）。
    // `setTimeout` は `requestCredential` の同期部分で呼ばれるので、呼び出し直後に差し戻せる。
    const realSetTimeout = globalThis.setTimeout;
    let requestedDelay: number | undefined;
    globalThis.setTimeout = ((handler: TimerHandler, delay?: number, ...args: unknown[]) => {
      requestedDelay = delay;
      return realSetTimeout(handler, 10, ...args);
    }) as typeof globalThis.setTimeout;
    let pending: Promise<unknown>;
    try {
      pending = requestCredential(options(stallingBodyFetch()));
    } finally {
      globalThis.setTimeout = realSetTimeout;
    }
    // タイムアウトが本文読み出しまで生きていた証拠（短縮していなければ 10 秒待つ値）。
    expect(requestedDelay).toBe(10_000);

    // 退行時（`clearTimeout` が本文読了より前）は abort が届かず待ちが**無期限**になる。
    // CI をハングさせずに「失敗」として落とすため、テスト側でも有限時間で打ち切る。
    const hung = Symbol('hung');
    const outcome = await Promise.race([
      pending.then(
        () => undefined,
        (error: unknown) => error,
      ),
      new Promise<symbol>((resolve) => {
        setTimeout(() => resolve(hung), 1_000);
      }),
    ]);
    expect(outcome).not.toBe(hung);
    expect(outcome).toBeInstanceOf(VericertsError);
    expect(outcome).toMatchObject({ code: ErrorCodes.ISSUER_COMMUNICATION_FAILED });
  });
});
