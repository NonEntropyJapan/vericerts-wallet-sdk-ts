/**
 * W2W 移行 API の `Object.prototype` 汚染耐性テスト。
 *
 * `startDeviceMigration` / `acceptDeviceMigration` / `completeMigration` が依存注入 `deps` の関数メンバを
 * 鎖読みすると、**省略した**依存を汚染された関数が埋める:
 *
 * - `nowSec`: 期限切れ招待が受理される（4031 の迂回）。
 * - `generateNonce`: 招待 nonce が攻撃者の固定値になる。
 * - `revokeOldDevice`: full 移行で旧端末の失効が行われないまま成功する。
 * - `ttlSec`: 招待の有効期間が攻撃者の値になる。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  acceptDeviceMigration,
  buildTransferOffer,
  completeMigration,
  startDeviceMigration,
} from '../../migration.js';
import type { MigrationSession } from '../../types.js';

const OLD_DID = 'did:peer:2.OldDevice';
const NEW_DID = 'did:peer:2.NewDevice';
const ZERO_NONCE = 'A'.repeat(43);

function session(): MigrationSession {
  return { session_id: 's', theirDID: OLD_DID, state: 'connected', credentialCount: 0, nonce: 'n' };
}

describe('startDeviceMigration の Object.prototype 汚染耐性', () => {
  it('継承した generateNonce は採用せず、nonce が毎回ランダムになる', () => {
    const [a, b] = withPollutedPrototype({ generateNonce: () => new Uint8Array(32) }, () => [
      startDeviceMigration(OLD_DID),
      startDeviceMigration(OLD_DID),
    ]);
    expect(a?.nonce).not.toBe(ZERO_NONCE);
    expect(a?.nonce).not.toBe(b?.nonce);
  });

  it('継承した generateId / nowSec / ttlSec は採用しない', () => {
    const before = Math.floor(Date.now() / 1000);
    const inv = withPollutedPrototype(
      { generateId: () => 'attacker-id', nowSec: () => 0, ttlSec: 10 ** 9 },
      () => startDeviceMigration(OLD_DID),
    );
    expect(inv.id).not.toBe('attacker-id');
    expect(inv.expiresTime).toBeGreaterThanOrEqual(before + 3600);
    expect(inv.expiresTime).toBeLessThan(before + 3600 + 60);
  });

  it('明示的に渡した依存注入は従来どおり効く', () => {
    const inv = startDeviceMigration(OLD_DID, {
      generateId: () => 'id-1',
      generateNonce: () => new Uint8Array(32).fill(7),
      nowSec: () => 1000,
      ttlSec: 10,
    });
    expect(inv.id).toBe('id-1');
    expect(inv.expiresTime).toBe(1010);
  });
});

describe('acceptDeviceMigration の Object.prototype 汚染耐性', () => {
  it('継承した nowSec で期限切れ招待を受理しない（4031）', async () => {
    const inv = startDeviceMigration(OLD_DID, { nowSec: () => 1000, ttlSec: 10 });
    // 実時刻は招待の期限（1010）を大きく過ぎている。汚染値 0 を拾えば受理されてしまう。
    await expect(
      withPollutedPrototypeAsync({ nowSec: () => 0 }, () =>
        acceptDeviceMigration(inv.invitationUri, { ourDID: NEW_DID }),
      ),
    ).rejects.toThrow(new VericertsError(ErrorCodes.W2W_ATTESTATION_FAILED));
  });

  it('継承した verifyAttestation / generateId は採用しない', async () => {
    const inv = startDeviceMigration(OLD_DID);
    const s = await withPollutedPrototypeAsync(
      { verifyAttestation: () => false, generateId: () => 'attacker-id' },
      () => acceptDeviceMigration(inv.invitationUri, { ourDID: NEW_DID }),
    );
    expect(s.state).toBe('connected');
    expect(s.session_id).not.toBe('attacker-id');
  });
});

describe('completeMigration の Object.prototype 汚染耐性', () => {
  it('継承した revokeOldDevice では full 移行を成功させない（4035）', async () => {
    await expect(
      withPollutedPrototypeAsync({ revokeOldDevice: () => true }, () =>
        completeMigration(session(), ['vc-1'], 'full', { transferCredential: () => true }),
      ),
    ).rejects.toThrow(new VericertsError(ErrorCodes.W2W_DOUBLE_ACTIVE));
  });

  it('継承した needsRebinding は採用せず、転送成功 VC すべてを要再バインドとする', async () => {
    const result = await withPollutedPrototypeAsync({ needsRebinding: () => false }, () =>
      completeMigration(session(), ['vc-1', 'vc-2'], 'selective', {
        transferCredential: () => true,
      }),
    );
    expect(result.rebindingRequired).toEqual(['vc-1', 'vc-2']);
  });

  it('明示的に渡した revokeOldDevice / needsRebinding は従来どおり効く', async () => {
    const revoked: string[][] = [];
    const result = await completeMigration(session(), ['vc-1', 'vc-2'], 'full', {
      transferCredential: () => true,
      revokeOldDevice: (ids) => {
        revoked.push([...ids]);
        return true;
      },
      needsRebinding: (id) => id === 'vc-2',
    });
    expect(revoked).toEqual([['vc-1', 'vc-2']]);
    expect(result.rebindingRequired).toEqual(['vc-2']);
  });
});

describe('buildTransferOffer の Object.prototype 汚染耐性', () => {
  it('継承した nowSec / generateId / ttlSec は採用しない', () => {
    const before = Math.floor(Date.now() / 1000);
    const offer = withPollutedPrototype(
      { nowSec: () => 0, generateId: () => 'attacker-id', ttlSec: 10 ** 9 },
      () =>
        buildTransferOffer(session(), NEW_DID, {
          credential_count: 1,
          formats: ['jwt'],
          total_size_bytes: 1,
          transfer_mode: 'full',
        } as never),
    );
    expect(offer.id).not.toBe('attacker-id');
    expect(offer.created_time).toBeGreaterThanOrEqual(before);
    expect(offer.expires_time - offer.created_time).toBe(3600);
  });
});
