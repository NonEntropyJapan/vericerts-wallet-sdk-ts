/**
 * `requestCNonce` のリダイレクト先 HTTPS 検査の回帰テスト。
 *
 * 判定は `startsWith('https://')` ではなく共有述語 `internal/https-url.ts` の `isHttpsUrl` で行う。
 * `'https://'`（ホスト無し）は `startsWith` を通るが `new URL()` が投げるため `isHttpsUrl` では落ちる。
 * 取得前の URL とリダイレクト後の最終応答 URL の両方に、同じ HTTPS 検査を適用する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FetchLike } from '../../../../fetch-di.js';
import { requestCNonce } from '../nonce.js';

const NONCE_ENDPOINT = 'https://issuer.example/nonce';

/** `response.url` を任意の値に固定した応答を返す fetch ダブル（`Response.url` は代入できない）。 */
function stubFetchWithFinalUrl(finalUrl: string): FetchLike {
  return async () =>
    ({
      ok: true,
      status: 200,
      url: finalUrl,
      headers: new Headers(),
      text: async () => JSON.stringify({ c_nonce: 'abc' }),
    }) as unknown as Response;
}

/** `requestCNonce` が投げた `VericertsError` を捕まえる。 */
async function catchRequestCNonce(fetchImpl: FetchLike): Promise<VericertsError | undefined> {
  try {
    await requestCNonce(NONCE_ENDPOINT, fetchImpl);
    return undefined;
  } catch (error) {
    return error instanceof VericertsError ? error : undefined;
  }
}

describe('requestCNonce のリダイレクト先 HTTPS 検査', () => {
  it("ホスト無しの 'https://' へ着地した応答を insecure_redirect で拒否する", async () => {
    const caught = await catchRequestCNonce(stubFetchWithFinalUrl('https://'));
    expect(caught).toBeInstanceOf(VericertsError);
    expect(caught?.code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
    expect(caught?.context).toMatchObject({ reason: 'insecure_redirect' });
  });

  it('平文 HTTP へ着地した応答を insecure_redirect で拒否する', async () => {
    const caught = await catchRequestCNonce(stubFetchWithFinalUrl('http://issuer.example/nonce'));
    expect(caught?.context).toMatchObject({ reason: 'insecure_redirect' });
  });

  it('HTTPS の最終 URL は通す', async () => {
    expect(await requestCNonce(NONCE_ENDPOINT, stubFetchWithFinalUrl(NONCE_ENDPOINT))).toBe('abc');
  });
});
