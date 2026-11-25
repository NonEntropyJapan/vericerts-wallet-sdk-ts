/**
 * W2W デバイス移行プロトコルの統合テスト。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../errors.js';
import {
  acceptDeviceMigration,
  buildTransferOffer,
  completeMigration,
  parseInvitation,
  startDeviceMigration,
} from '../migration.js';
import { W2W_MESSAGE_TYPES } from '../types.js';

const OLD_DID = 'did:peer:2.OldDevice';
const NEW_DID = 'did:peer:2.NewDevice';

/** 固定 nonce / ID / 時刻を注入するヘルパ。 */
function fixedStartDeps(nowSec: number) {
  let n = 0;
  return {
    generateId: () => `id-${n++}`,
    generateNonce: () => new Uint8Array(32).fill(7),
    nowSec: () => nowSec,
    ttlSec: 3600,
  };
}

describe('startDeviceMigration / parseInvitation', () => {
  it('produces an OOB invitation with nonce and parseable URI', () => {
    const inv = startDeviceMigration(OLD_DID, fixedStartDeps(1_000_000));
    expect(inv.from).toBe(OLD_DID);
    expect(inv.expiresTime).toBe(1_000_000 + 3600);
    expect(inv.invitationUri.startsWith('openid-w2w://invite?')).toBe(true);

    const parsed = parseInvitation(inv.invitationUri);
    expect(parsed.from).toBe(OLD_DID);
    expect(parsed.nonce).toBe(inv.nonce);
    expect(parsed.expiresTime).toBe(inv.expiresTime);
  });

  it('rejects a malformed invitation URI (4031)', () => {
    expect(() => parseInvitation('not-a-uri')).toThrow(VericertsError);
    expect(() => parseInvitation('openid-w2w://invite?id=x')).toThrow(VericertsError);
  });
});

describe('acceptDeviceMigration', () => {
  it('establishes a connected session from a valid invitation', async () => {
    const inv = startDeviceMigration(OLD_DID, fixedStartDeps(1_000_000));
    const session = await acceptDeviceMigration(inv.invitationUri, {
      ourDID: NEW_DID,
      nowSec: () => 1_000_100,
    });
    expect(session.state).toBe('connected');
    expect(session.theirDID).toBe(OLD_DID);
    expect(session.nonce).toBe(inv.nonce);
  });

  it('rejects an expired invitation (4031)', async () => {
    const inv = startDeviceMigration(OLD_DID, fixedStartDeps(1_000_000));
    const promise = acceptDeviceMigration(inv.invitationUri, {
      ourDID: NEW_DID,
      nowSec: () => 1_000_000 + 3601,
    });
    await expect(promise).rejects.toMatchObject({ code: '4031' });
  });

  it('rejects when attestation verification fails (4031)', async () => {
    const inv = startDeviceMigration(OLD_DID, fixedStartDeps(1_000_000));
    const promise = acceptDeviceMigration(inv.invitationUri, {
      ourDID: NEW_DID,
      nowSec: () => 1_000_100,
      verifyAttestation: () => false,
    });
    await expect(promise).rejects.toMatchObject({ code: '4031' });
  });
});

describe('buildTransferOffer', () => {
  it('builds a transfer-offer message', async () => {
    const inv = startDeviceMigration(OLD_DID, fixedStartDeps(1_000_000));
    const session = await acceptDeviceMigration(inv.invitationUri, {
      ourDID: NEW_DID,
      nowSec: () => 1_000_100,
    });
    const offer = buildTransferOffer(
      session,
      OLD_DID,
      {
        credential_count: 12,
        formats: ['vc+sd-jwt', 'mso_mdoc'],
        total_size_bytes: 204800,
        require_passphrase: true,
        transfer_mode: 'full',
      },
      { nowSec: () => 1_745_000_000, generateId: () => 'msg-1' },
    );
    expect(offer.type).toBe(W2W_MESSAGE_TYPES.TRANSFER_OFFER);
    expect(offer.to).toEqual([OLD_DID]);
    expect(offer.body.transfer_mode).toBe('full');
    expect(offer.expires_time).toBeGreaterThan(offer.created_time);
  });

  // `formats` は「旧端末が実際に保持しているフォーマットの列挙」であり、
  // その算出は呼び出し側の責務で SDK は導出しない（body をそのまま載せる）。
  // 新旧いずれの SD-JWT VC 識別子も列挙でき、双方保持時は双方を広告できることを固定する。
  it('passes body.formats through verbatim, including both SD-JWT VC identifiers', async () => {
    const inv = startDeviceMigration(OLD_DID, fixedStartDeps(1_000_000));
    const session = await acceptDeviceMigration(inv.invitationUri, {
      ourDID: NEW_DID,
      nowSec: () => 1_000_100,
    });
    const formats = ['dc+sd-jwt', 'vc+sd-jwt', 'mso_mdoc'];
    const offer = buildTransferOffer(
      session,
      OLD_DID,
      {
        credential_count: 12,
        formats,
        total_size_bytes: 204800,
        require_passphrase: true,
        transfer_mode: 'full',
      },
      { nowSec: () => 1_745_000_000, generateId: () => 'msg-1' },
    );
    // 期待値はリテラルで持つ。`formats` から派生させると buildTransferOffer が body を
    // 参照のまま載せる（migration.ts の `body,`）ため実際値と期待値が同一配列となり、
    // in-place の並べ替え・正規化が入っても両辺が同時に変化して検知できないためである。
    expect(offer.body.formats).toEqual(['dc+sd-jwt', 'vc+sd-jwt', 'mso_mdoc']);
  });
});

describe('completeMigration (full end-to-end)', () => {
  async function connectedSession() {
    const inv = startDeviceMigration(OLD_DID, fixedStartDeps(1_000_000));
    return acceptDeviceMigration(inv.invitationUri, {
      ourDID: NEW_DID,
      nowSec: () => 1_000_100,
    });
  }

  it('transfers all VCs and revokes old device in full mode', async () => {
    const session = await connectedSession();
    const revoked: string[][] = [];
    const result = await completeMigration(session, ['vc-1', 'vc-2', 'vc-3'], 'full', {
      transferCredential: () => true,
      revokeOldDevice: (ids) => {
        revoked.push([...ids]);
        return true;
      },
    });
    expect(result.transferred).toBe(3);
    expect(result.failed).toEqual([]);
    expect(result.rebindingRequired).toEqual(['vc-1', 'vc-2', 'vc-3']);
    expect(revoked).toEqual([['vc-1', 'vc-2', 'vc-3']]);
    expect(session.state).toBe('completed');
    expect(session.credentialCount).toBe(3);
  });

  it('records failed transfers without aborting', async () => {
    const session = await connectedSession();
    const result = await completeMigration(session, ['vc-1', 'vc-2'], 'selective', {
      transferCredential: (id) => id !== 'vc-2',
    });
    expect(result.transferred).toBe(1);
    expect(result.failed).toEqual(['vc-2']);
  });

  it('does NOT revoke old device in selective mode', async () => {
    const session = await connectedSession();
    let revokeCalled = false;
    await completeMigration(session, ['vc-1'], 'selective', {
      transferCredential: () => true,
      revokeOldDevice: () => {
        revokeCalled = true;
        return true;
      },
    });
    expect(revokeCalled).toBe(false);
  });

  it('throws 4035 when old-device revocation fails in full mode', async () => {
    const session = await connectedSession();
    const promise = completeMigration(session, ['vc-1'], 'full', {
      transferCredential: () => true,
      revokeOldDevice: () => false,
    });
    await expect(promise).rejects.toMatchObject({ code: '4035' });
  });

  // revokeOldDevice 未指定を「旧端末無効化の失敗」として扱う（fail-open の是正）。
  // full モードでは旧端末 VC の失効が必要なため、DI 忘れは 4035 で通知しなければならず、
  // 黙って 'completed' を返してはならない。
  it('throws 4035 when revokeOldDevice is omitted in full mode (does not silently succeed)', async () => {
    const session = await connectedSession();
    const promise = completeMigration(session, ['vc-1'], 'full', {
      transferCredential: () => true,
      // revokeOldDevice omitted on purpose
    });
    await expect(promise).rejects.toMatchObject({ code: '4035' });
    expect(session.state).not.toBe('completed');
  });

  it('honors custom needsRebinding predicate', async () => {
    const session = await connectedSession();
    const result = await completeMigration(session, ['vc-1', 'vc-2'], 'clone', {
      transferCredential: () => true,
      needsRebinding: (id) => id === 'vc-2',
    });
    expect(result.rebindingRequired).toEqual(['vc-2']);
  });
});

describe('parseInvitation — exp は厳密な 10 進整数のみ', () => {
  const uri = (exp: string) => `openid-w2w://invite?id=x&from=did%3Aexample%3Aa&nonce=n&exp=${exp}`;

  it('正常な 10 進整数を受理する', () => {
    expect(parseInvitation(uri('1700000000')).expiresTime).toBe(1_700_000_000);
  });

  it("'123abc' / '1e3' / '-5' / '0x10' / '1.9' / '+5' / 空 / 16 桁以上は W2W_ATTESTATION_FAILED", () => {
    for (const exp of ['123abc', '1e3', '-5', '0x10', '1.9', '+5', '', '%20', '1234567890123456']) {
      expect(() => parseInvitation(uri(exp))).toThrow(VericertsError);
    }
  });
});
