/**
 * Entity Statement 取得の共通経路（`fetchStatementJwt`）。
 *
 * Entity Configuration と Subordinate Statement の取得ハードニングは同じ関数を通る。
 * 取得失敗が常に `FEDERATION_FETCH_FAILED`（5011）で、1 MiB 超だけが理由付きになることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../../../errors.js';
import { OVERSIZED_BODY_REASON } from '../../../../http/body-limit.js';
import { fetchStatementJwt } from '../../statement/fetch-statement.js';

const URL = 'https://federation.example/.well-known/openid-federation';

function respond(body: string, init: ResponseInit = {}): typeof fetch {
  return (async () =>
    new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/entity-statement+jwt' },
      ...init,
    })) as unknown as typeof fetch;
}

async function failureOf(fetchFn: typeof fetch): Promise<VericertsError> {
  const error = await fetchStatementJwt(URL, fetchFn).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(VericertsError);
  return error as VericertsError;
}

describe('fetchStatementJwt', () => {
  it('許可された Content-Type の本文を trim して返す', async () => {
    expect(await fetchStatementJwt(URL, respond('  a.b.c\n'))).toBe('a.b.c');
  });

  const failures: readonly [string, typeof fetch][] = [
    ['HTTP エラー', respond('x', { status: 500 })],
    ['未許可の Content-Type', respond('a.b.c', { headers: { 'content-type': 'text/html' } })],
    ['空本文', respond('   ')],
    [
      'ネットワークエラー',
      (async () => {
        throw new Error('boom');
      }) as unknown as typeof fetch,
    ],
  ];

  for (const [label, fetchFn] of failures) {
    it(`${label}は FEDERATION_FETCH_FAILED（5011）で理由は付かない`, async () => {
      const error = await failureOf(fetchFn);

      expect(error.code).toBe('5011');
      expect(error.context?.reason).toBeUndefined();
    });
  }

  it('1 MiB 超は FEDERATION_FETCH_FAILED のまま oversized の理由が立つ（FO-6 から除外するため）', async () => {
    const error = await failureOf(
      respond('a'.repeat(1024 * 1024 + 1), {
        headers: { 'content-type': 'application/jwt' },
      }),
    );

    expect(error.code).toBe('5011');
    expect(error.context?.reason).toBe(OVERSIZED_BODY_REASON);
  });

  it('リダイレクト先が非公開ホストなら追従せず 5011', async () => {
    const fetchFn = (async (input: RequestInfo | URL) =>
      String(input).startsWith('https://federation.example')
        ? new Response(null, { status: 302, headers: { location: 'https://127.0.0.1/x' } })
        : respond('a.b.c')(input)) as unknown as typeof fetch;

    expect((await failureOf(fetchFn)).code).toBe('5011');
  });
});
