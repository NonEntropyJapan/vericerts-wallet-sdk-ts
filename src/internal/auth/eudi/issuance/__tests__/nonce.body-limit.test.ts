/**
 * `requestCNonce` の入口検査（本文バイト上限）の回帰テスト。
 *
 * Nonce Endpoint の応答は `c_nonce` を 1 個返すだけで数十バイトあれば足り、巨大な本文は DoS 以外の
 * 意味を持たない。上限は `http/body-limit.ts` の `MAX_DOCUMENT_BYTES`（1 MiB）で、宣言値
 * （`content-length`）と実バイト数の双方に課す。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FetchLike } from '../../../../fetch-di.js';
import { MAX_DOCUMENT_BYTES } from '../../../../http/body-limit.js';
import { requestCNonce } from '../nonce.js';

const NONCE_ENDPOINT = 'https://issuer.example/nonce';

/** 常に同じ `Response` を返す fetch スタブ。 */
function stubFetch(response: Response): FetchLike {
  return async () => response;
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

describe('requestCNonce の本文バイト上限', () => {
  it('上限以内の応答からは c_nonce を返す', async () => {
    const response = new Response(JSON.stringify({ c_nonce: 'abc' }), { status: 200 });
    expect(await requestCNonce(NONCE_ENDPOINT, stubFetch(response))).toBe('abc');
  });

  it('MAX_DOCUMENT_BYTES を超える本文は 8010（oversized_body）で拒否する', async () => {
    const huge = `{"c_nonce":"${'a'.repeat(MAX_DOCUMENT_BYTES)}"}`;
    const caught = await catchRequestCNonce(stubFetch(new Response(huge, { status: 200 })));
    expect(caught).toBeInstanceOf(VericertsError);
    expect(caught?.code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
    expect(caught?.context).toMatchObject({ reason: 'oversized_body' });
  });

  it('content-length が上限超過を宣言する応答は本文を読む前に拒否する', async () => {
    const response = new Response(JSON.stringify({ c_nonce: 'abc' }), {
      status: 200,
      headers: { 'content-length': String(MAX_DOCUMENT_BYTES + 1) },
    });
    const caught = await catchRequestCNonce(stubFetch(response));
    expect(caught?.code).toBe(ErrorCodes.TOKEN_REQUEST_FAILED);
    expect(caught?.context).toMatchObject({ reason: 'oversized_body' });
  });
});
