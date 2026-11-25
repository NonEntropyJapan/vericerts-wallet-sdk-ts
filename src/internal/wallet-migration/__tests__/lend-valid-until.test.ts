/**
 * Lend の `valid_until` 解釈の回帰テスト。
 *
 * 新規発行は厳格な ISO 8601 だけを受理するが、発行済みトークンの判定は日付のみも受理し、
 * 解釈できない値では**失効させない**（失効は取り消せず、`valid_until` は署名対象で直せない）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../errors.js';
import { expireOverdueLends, redeemLend } from '../lend.js';
import { testPublicKeyJwk } from './fixtures.js';
import { lendToken, NOW } from './lend-fixtures.js';

describe('expireOverdueLends / redeemLend の valid_until 解釈', () => {
  // 回帰テスト: 失効は永続化されて取り消せず、`valid_until` は署名対象なので後から直せない。
  // 読めない値を「期限切れ」と断じると、パーサを厳しくした更新だけで期限内のトークンが不可逆に死ぬ。
  // 能動的な掃除は「期限切れだと証明できるもの」に限り、証明できないものは引き換えの入口で拒否する。
  it('does not revoke a token whose valid_until cannot be parsed', async () => {
    const store = new Set<string>();
    const expired = await expireOverdueLends([lendToken('broken', 'not-a-date')], {
      markRevoked: (id) => void store.add(id),
      now: () => NOW,
    });
    expect(expired).toEqual([]);
    expect([...store]).toEqual([]);
  });

  it('still refuses to redeem a token whose valid_until cannot be parsed (fail-closed)', () => {
    expect(() =>
      redeemLend(lendToken('broken', 'not-a-date'), {
        now: () => NOW,
        lenderPublicKeyJwk: testPublicKeyJwk(),
      }),
    ).toThrow(expect.objectContaining({ code: ErrorCodes.W2W_LEND_EXPIRED }));
  });

  // 旧版が `Date.parse` で受理して保存した日付のみ（`YYYY-MM-DD`）のトークンを、更新だけで失効させない。
  it('keeps a date-only valid_until that has not passed yet', async () => {
    const store = new Set<string>();
    const expired = await expireOverdueLends([lendToken('date-only', '2099-12-31')], {
      markRevoked: (id) => void store.add(id),
      now: () => NOW,
    });
    expect(expired).toEqual([]);
    expect([...store]).toEqual([]);
  });

  it('expires a date-only valid_until that has passed', async () => {
    const store = new Set<string>();
    const expired = await expireOverdueLends([lendToken('old', '2020-01-01')], {
      markRevoked: (id) => void store.add(id),
      now: () => NOW,
    });
    expect(expired).toEqual(['old']);
    expect([...store]).toEqual(['old']);
  });
});
