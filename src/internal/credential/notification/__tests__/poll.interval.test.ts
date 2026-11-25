/**
 * poll 購読の `intervalMs` 検証（`scheduleLendExpiryChecks` の）。
 *
 * NaN / 0 / 負値 / Infinity / タイマー上限超過は `setInterval` で約 1ms に丸められ、Issuer へ
 * 連続 GET が飛ぶ。購読時点で RangeError として拒否し、スケジューラも `fetchImpl` も起動しない。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { subscribeCredentialNotification } from '../subscribe.js';

const ISSUER_URL = 'https://issuer.example/notification';

describe('subscribeCredentialNotification(poll): intervalMs 検証', () => {
  it.each([
    ['NaN', Number.NaN],
    ['0', 0],
    ['負値', -1],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['タイマー上限超過', 2 ** 31],
    ['文字列', '1000' as unknown as number],
  ])('intervalMs=%s は RangeError で拒否し、スケジューラも fetch も起動しない', async (_name, intervalMs) => {
    let scheduled = 0;
    let fetched = 0;
    const fetchImpl: FetchLike = async () => {
      fetched++;
      return new Response('[]', { status: 200 });
    };

    await expect(
      subscribeCredentialNotification(ISSUER_URL, 'poll', async () => undefined, {
        intervalMs,
        fetchImpl,
        schedule: () => {
          scheduled++;
          return () => undefined;
        },
      }),
    ).rejects.toThrow(RangeError);
    expect(scheduled).toBe(0);
    expect(fetched).toBe(0);
  });

  it('有限な正の intervalMs はそのままスケジューラへ渡す', async () => {
    const seen: number[] = [];
    const sub = await subscribeCredentialNotification(ISSUER_URL, 'poll', async () => undefined, {
      intervalMs: 250,
      schedule: (_task, ms) => {
        seen.push(ms);
        return () => undefined;
      },
    });
    await sub.unsubscribe();
    expect(seen).toEqual([250]);
  });
});
