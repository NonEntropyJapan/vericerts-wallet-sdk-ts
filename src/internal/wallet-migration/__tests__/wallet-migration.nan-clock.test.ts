/**
 * W2W 移行・Lend の期限判定が非有限（NaN / ±Infinity）の注入時刻で fail-open しないことの回帰テスト。
 *
 * `expiryMs <= now` / `expiresTime <= nowSec` は NaN で常に `false` になり、期限切れの Lend トークン・
 * 招待を受理する。修正前は `redeemLend` / `acceptDeviceMigration` が例外を出さず落ちる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { createLend, redeemLend } from '../lend.js';
import { acceptDeviceMigration, startDeviceMigration } from '../migration.js';
import { testSigner } from './fixtures.js';

const NON_FINITE = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY] as const;
const NOW = Date.parse('2026-05-01T00:00:00Z');

describe('redeemLend: 非有限の now() は 4034 で拒否する', () => {
  const signer = testSigner('did:key:lender#0');
  const lender = { did: 'did:peer:2.Lender', signer };
  const token = createLend(
    ['vc-1'],
    '2026-06-01T00:00:00Z',
    'did:peer:2.Tablet',
    lender,
    {},
    {
      now: () => NOW,
    },
  );

  it('有限時刻の従来挙動（期限内は引き換え可、期限後は 4034）', () => {
    expect(redeemLend(token, { lenderPublicKeyJwk: signer.publicKeyJwk, now: () => NOW })).toEqual([
      'vc-1',
    ]);
    expect(() =>
      redeemLend(token, {
        lenderPublicKeyJwk: signer.publicKeyJwk,
        now: () => Date.parse('2026-07-01T00:00:00Z'),
      }),
    ).toThrow(new VericertsError(ErrorCodes.W2W_LEND_EXPIRED));
  });

  for (const bad of NON_FINITE) {
    it(`now() = ${bad}: 期限切れ相当（判定不能）として 4034`, () => {
      expect(() =>
        redeemLend(token, { lenderPublicKeyJwk: signer.publicKeyJwk, now: () => bad }),
      ).toThrow(new VericertsError(ErrorCodes.W2W_LEND_EXPIRED));
    });
  }
});

describe('acceptDeviceMigration: 非有限の nowSec() は 4031 で拒否する', () => {
  const inv = startDeviceMigration('did:peer:2.OldDevice', {
    generateId: () => 'id-1',
    nowSec: () => 1_000_000,
  });

  for (const bad of NON_FINITE) {
    it(`nowSec() = ${bad}: 期限切れ招待を受理しない`, async () => {
      await expect(
        acceptDeviceMigration(inv.invitationUri, {
          ourDID: 'did:peer:2.NewDevice',
          nowSec: () => bad,
        }),
      ).rejects.toThrow(new VericertsError(ErrorCodes.W2W_ATTESTATION_FAILED));
    });
  }
});
