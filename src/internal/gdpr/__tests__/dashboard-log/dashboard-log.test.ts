/**
 * DashboardLog（Dashboard ログ追記・読み出し・purge）の単体テスト。
 *
 * - append は JWS 署名付きエントリを返し、署名が signer の公開鍵で検証可能（改ざん検知の基盤）。
 * - 連続 append で prevHash が直前エントリの signing-input SHA-256 に連結される（Merkle chain）。
 * - 先頭エントリの prevHash は null。
 * - list は追記順（連番昇順）で返す。
 * - recorded payload は与えた内容と一致し、type が保持される。
 * - purge はユーザー制御ログを filter（olderThan / types / rpIdentifier、AND 条件）で一括削除し
 *   件数を返す。削除監査記録（deletion-log/）は対象外（GDPR Art.17 削除権）。
 *
 * exportLog / importLog はテスト量が多いため `dashboard-log-export.test.ts` /
 * `dashboard-log-import.test.ts` に分割している。共有 signer / now ヘルパは
 * `dashboard-log-helpers.ts`。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { MemoryStorage } from '../../../../storage/storage.js';
import { decodeCompactJws, verifyWithJwk } from '../../../credential/vc/jws.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

describe('DashboardLog', () => {
  it('append は JWS 署名付きエントリを返し、signer 公開鍵で検証できる', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));

    const entry = await log.append(
      'correctionRequest',
      { vcId: 'vc-1', reason: '氏名誤り' },
      signer,
    );

    expect(entry.type).toBe('correctionRequest');
    expect(entry.payload).toEqual({ vcId: 'vc-1', reason: '氏名誤り' });
    expect(entry.recordedAt).toBe('2026-07-02T00:00:00.000Z');
    expect(entry.prevHash).toBeNull();

    // 署名（コンパクト JWS）を signer の公開鍵で検証できる。
    const decoded = decodeCompactJws(entry.signature);
    expect(verifyWithJwk('ES256K', decoded, signer.publicKeyJwk)).toBe(true);
    // 署名対象の payload に type / payload / recordedAt / prevHash が含まれる（改ざん検知の対象）。
    expect(decoded.payload.type).toBe('correctionRequest');
    expect(decoded.payload.prevHash).toBeNull();
  });

  it('連続 append で prevHash が直前エントリの signing-input SHA-256 に連結される', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));

    const first = await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    const second = await log.append('correctionRequest', { vcId: 'vc-2', reason: 'b' }, signer);

    expect(first.prevHash).toBeNull();
    // second.prevHash は first の signing-input（header.payload）の SHA-256（base64url）。
    const firstSigningInput = first.signature.split('.').slice(0, 2).join('.');
    const expected = base64urlnopad.encode(sha256(new TextEncoder().encode(firstSigningInput)));
    expect(second.prevHash).toBe(expected);
  });

  it('list は追記順（連番昇順）で返す', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());

    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    await log.append('correctionRequest', { vcId: 'vc-2', reason: 'b' }, signer);
    await log.append('correctionRequest', { vcId: 'vc-3', reason: 'c' }, signer);

    const entries = await log.list();
    expect(entries.map((e) => (e.payload as { vcId: string }).vcId)).toEqual([
      'vc-1',
      'vc-2',
      'vc-3',
    ]);
    // ID は連番ゼロ埋めで昇順。
    expect(entries.map((e) => e.id)).toEqual(['000000000000', '000000000001', '000000000002']);
  });

  it('空ログの list は空配列', async () => {
    const log = new DashboardLog(new MemoryStorage());
    expect(await log.list()).toEqual([]);
  });
});

describe('DashboardLog purge', () => {
  it('filter なしはユーザー制御ログを全削除し、削除件数を返す', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    await log.append('correctionRequest', { vcId: 'vc-2', reason: 'b' }, signer);

    const deleted = await log.purge();

    expect(deleted).toBe(2);
    expect(await log.list()).toEqual([]);
  });

  it('削除監査記録（deletion-log/）は purge の対象外', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    await log.appendDeletionRecord('vc-9', signer);

    const deleted = await log.purge();

    expect(deleted).toBe(1);
    expect(await log.list()).toEqual([]);
    // 削除監査記録は保全される。
    const records = await log.listDeletionRecords();
    expect(records.map((e) => (e.payload as { vcId: string }).vcId)).toEqual(['vc-9']);
  });

  it('olderThan は当該日時より前のエントリのみ削除する', async () => {
    const signer = testSigner();
    const storage = new MemoryStorage();
    const early = new DashboardLog(storage, fixedNow('2026-01-01T00:00:00.000Z'));
    await early.append('correctionRequest', { vcId: 'old', reason: 'a' }, signer);
    const late = new DashboardLog(storage, fixedNow('2026-06-01T00:00:00.000Z'));
    await late.append('correctionRequest', { vcId: 'new', reason: 'b' }, signer);

    const deleted = await late.purge({ olderThan: '2026-03-01T00:00:00.000Z' });

    expect(deleted).toBe(1);
    const remaining = await late.list();
    expect(remaining.map((e) => (e.payload as { vcId: string }).vcId)).toEqual(['new']);
  });

  it('types は指定種別のエントリのみ削除する', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    await log.append('consentRevoked', { scope: { purpose: 'kyc' } }, signer);
    await log.append('presentation', { rpIdentifier: 'rp-1' }, signer);

    const deleted = await log.purge({ types: ['correctionRequest', 'presentation'] });

    expect(deleted).toBe(2);
    const remaining = await log.list();
    expect(remaining.map((e) => e.type)).toEqual(['consentRevoked']);
  });

  it('rpIdentifier は payload 直下 / scope.rpIdentifier のいずれか一致を削除する', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());
    await log.append('presentation', { rpIdentifier: 'rp-A' }, signer);
    await log.append('consentRevoked', { scope: { rpIdentifier: 'rp-A' } }, signer);
    await log.append('presentation', { rpIdentifier: 'rp-B' }, signer);

    const deleted = await log.purge({ rpIdentifier: 'rp-A' });

    expect(deleted).toBe(2);
    const remaining = await log.list();
    expect(remaining.map((e) => (e.payload as { rpIdentifier: string }).rpIdentifier)).toEqual([
      'rp-B',
    ]);
  });

  it('複数条件は AND で適用する（すべて満たすエントリのみ削除）', async () => {
    const signer = testSigner();
    const storage = new MemoryStorage();
    const early = new DashboardLog(storage, fixedNow('2026-01-01T00:00:00.000Z'));
    // 古い + presentation + rp-A（全条件一致）。
    await early.append('presentation', { rpIdentifier: 'rp-A' }, signer);
    // 古い + presentation だが rp-B（rpIdentifier 不一致）。
    await early.append('presentation', { rpIdentifier: 'rp-B' }, signer);
    const late = new DashboardLog(storage, fixedNow('2026-06-01T00:00:00.000Z'));
    // 新しい + presentation + rp-A（olderThan 不一致）。
    await late.append('presentation', { rpIdentifier: 'rp-A' }, signer);

    const deleted = await late.purge({
      olderThan: '2026-03-01T00:00:00.000Z',
      types: ['presentation'],
      rpIdentifier: 'rp-A',
    });

    expect(deleted).toBe(1);
    const remaining = await late.list();
    expect(remaining).toHaveLength(2);
  });

  it('一致なしは 0 を返し何も削除しない', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);

    const deleted = await log.purge({ types: ['authFailure'] });

    expect(deleted).toBe(0);
    expect(await log.list()).toHaveLength(1);
  });

  it('空ログの purge は 0 を返す', async () => {
    const log = new DashboardLog(new MemoryStorage());
    expect(await log.purge()).toBe(0);
  });
});

describe('DashboardLog append 採番衝突（回帰）', () => {
  it('purge で低番のみ削除後の append は既存 ID と衝突せず監査ログを破壊しない', async () => {
    const signer = testSigner();
    const storage = new MemoryStorage();
    const log = new DashboardLog(storage);

    await log.append('presentation', { rpIdentifier: 'rp-A' }, signer); // seq 0
    await log.append('presentation', { rpIdentifier: 'rp-A' }, signer); // seq 1
    const survivor = await log.append('presentation', { rpIdentifier: 'rp-B' }, signer); // seq 2
    expect(survivor.id).toBe('000000000002');

    // rp-A（低番 seq 0,1）のみ削除。survivor（seq 2, rp-B）が残る。
    const deleted = await log.purge({ rpIdentifier: 'rp-A' });
    expect(deleted).toBe(2);

    // 採番が件数（keys.length=1 → seq 1）ではなく最大 seq+1（=3）になること。
    const appended = await log.append('presentation', { rpIdentifier: 'rp-C' }, signer);
    expect(appended.id).toBe('000000000003');

    // survivor（seq 2）が上書きされず残っていること（監査ログ破壊なし）。
    const entries = await log.list();
    expect(entries.map((e) => (e.payload as { rpIdentifier: string }).rpIdentifier)).toEqual([
      'rp-B',
      'rp-C',
    ]);
    // 新エントリの prevHash は残存末尾（survivor, seq 2）の signing-input ハッシュに連結される。
    const survivorSigningInput = survivor.signature.split('.').slice(0, 2).join('.');
    const expectedPrev = base64urlnopad.encode(
      sha256(new TextEncoder().encode(survivorSigningInput)),
    );
    expect(appended.prevHash).toBe(expectedPrev);
  });

  it('deleteEntriesForVc で低番のみ削除後の append も既存 ID と衝突しない', async () => {
    const signer = testSigner();
    const log = new DashboardLog(new MemoryStorage());

    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer); // seq 0
    const keep = await log.append('correctionRequest', { vcId: 'vc-2', reason: 'b' }, signer); // seq 1
    expect(keep.id).toBe('000000000001');

    const deleted = await log.deleteEntriesForVc('vc-1', signer); // seq 0 のみ削除
    expect(deleted).toBe(1);

    const appended = await log.append('correctionRequest', { vcId: 'vc-3', reason: 'c' }, signer);
    // 件数採番なら keys.length=1 → seq 1 で keep を上書きしていた。最大 seq+1 = 2 になる。
    expect(appended.id).toBe('000000000002');

    const entries = await log.list();
    expect(entries.map((e) => (e.payload as { vcId: string }).vcId)).toEqual(['vc-2', 'vc-3']);
  });
});
