/**
 * Art.17 削除監査記録（`deletion-log/`）の末尾（最新側）エントリ削除の検知。
 *
 * 末尾アンカーは `dashboard-log/` にしか無く、`credentialDeleted`（消去証跡）の末尾削除と
 * 同連番での再追記が痕跡なしでできた。`dashboard-log/` と同じアンカー機構を `deletion-log/` にも適用し、
 * `verify` が `deletion-log/` 自体の連鎖・末尾も検証して報告する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import { tailAnchorKeyFor } from '../../dashboard-log/dashboard-log-shared.js';
import type { DashboardLogIssue } from '../../log-integrity/chain.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

describe('deletion-log 末尾削除の検知', () => {
  const signer = testSigner();
  const verifierKey: DashboardLogVerifierKey = {
    alg: signer.alg,
    publicKeyJwk: signer.publicKeyJwk,
  };
  const keyOf = (seq: number) => `deletion-log/${String(seq).padStart(12, '0')}`;
  const tailIssue = (seq: number): DashboardLogIssue => ({
    id: keyOf(seq),
    reason: 'tailTruncated',
  });

  async function seeded(count: number): Promise<{ log: DashboardLog; storage: MemoryStorage }> {
    const storage = new MemoryStorage();
    const log = new DashboardLog(storage, fixedNow('2026-09-07T00:00:00.000Z'));
    for (let i = 0; i < count; i++) {
      await log.appendDeletionRecord(`vc-${i}`, signer);
    }
    return { log, storage };
  }

  it('無傷の削除記録（追記のみ）は ok のまま', async () => {
    const { log } = await seeded(3);
    await log.append('presentation', { clientId: 'rp' }, signer);
    expect((await log.verify(verifierKey)).ok).toBe(true);
  });

  it('末尾の credentialDeleted を削除すると tailTruncated として報告する', async () => {
    const { log, storage } = await seeded(3);
    await storage.delete(keyOf(2));

    const result = await log.verify(verifierKey);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([tailIssue(2)]);
  });

  it('末尾 2 件・全件の削除も検知する', async () => {
    const { log, storage } = await seeded(3);
    await storage.delete(keyOf(2));
    await storage.delete(keyOf(1));
    expect((await log.verify(verifierKey)).issues).toEqual([tailIssue(2)]);

    await storage.delete(keyOf(0));
    const empty = await log.verify(verifierKey);
    expect(empty.ok).toBe(false);
    expect(empty.issues.map((i) => i.reason)).toEqual(['tailTruncated']);
  });

  it('末尾削除後に同連番で再追記しても、アンカーが据え置かれ検知が続く', async () => {
    const { log, storage } = await seeded(3);
    await storage.delete(keyOf(2));
    await storage.delete(keyOf(1));
    await log.appendDeletionRecord('vc-other', signer); // 連番 1 を別内容で再利用
    expect((await log.verify(verifierKey)).ok).toBe(false);

    await log.appendDeletionRecord('vc-other-2', signer); // 連番 2: アンカー位置のハッシュ不一致
    const afterTwo = await log.verify(verifierKey);
    expect(afterTwo.ok).toBe(false);
    expect(afterTwo.issues).toEqual([tailIssue(2)]);

    await log.appendDeletionRecord('vc-other-3', signer);
    expect((await log.verify(verifierKey)).ok).toBe(false);
  });

  it('途中の欠損（連番の穴）も deletion-log 側の sequenceGap として報告する', async () => {
    const { log, storage } = await seeded(4);
    await storage.delete(keyOf(1));

    const result = await log.verify(verifierKey);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: keyOf(2), reason: 'sequenceGap' }]);
  });

  it('アンカーキーの破壊は「未導入」に畳まず報告する（deletion-log 用アンカー）', async () => {
    const { log, storage } = await seeded(2);
    await storage.set(tailAnchorKeyFor('deletion-log/'), new TextEncoder().encode('garbage'));

    const result = await log.verify(verifierKey);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: 'anchor/deletion-log', reason: 'tailTruncated' }]);
  });

  it('dashboard-log 側のアンカーとは独立している（片方の末尾削除がもう片方に波及しない）', async () => {
    const { log, storage } = await seeded(2);
    await log.append('presentation', { clientId: 'rp-0' }, signer);
    await log.append('presentation', { clientId: 'rp-1' }, signer);
    await storage.delete('dashboard-log/000000000001');

    const result = await log.verify(verifierKey);

    expect(result.issues).toEqual([{ id: '000000000001', reason: 'tailTruncated' }]);
  });
});
