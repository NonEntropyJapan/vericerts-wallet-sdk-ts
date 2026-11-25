/**
 * VC 単位削除（`deleteEntriesForVc` / `deleteCredential`）後の Dashboard ログの検証・移送。
 *
 * 削除証跡（`logEntryDeleted`）が無いと、正当な Art.17 削除が `verify` で `sequenceGap`（改ざん検知）と
 * 誤報告され続け、削除後の `exportLog` → `importLog` も `3010` で失敗する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { CredentialStore } from '../../credential-store/index.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

const signer = testSigner();
const verifierKey: DashboardLogVerifierKey = { alg: signer.alg, publicKeyJwk: signer.publicKeyJwk };

async function seeded(vcIds: readonly string[]) {
  const storage = new MemoryStorage();
  const log = new DashboardLog(storage, fixedNow('2026-10-01T00:00:00.000Z'));
  for (const vcId of vcIds) {
    await log.append('correctionRequest', { vcId, reason: 'r' }, signer);
  }
  return { storage, log };
}

describe('DashboardLog.deleteEntriesForVc の削除証跡', () => {
  it.each([
    ['先頭', 'vc-0'],
    ['中間', 'vc-1'],
    ['末尾', 'vc-2'],
  ])('%s のエントリを削除しても verify は ok（sequenceGap を誤報告しない）', async (_label, target) => {
    const { log } = await seeded(['vc-0', 'vc-1', 'vc-2']);

    expect(await log.deleteEntriesForVc(target, signer)).toBe(1);

    const result = await log.verify(verifierKey);
    expect(result.issues).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.count).toBe(2);
  });

  it('削除証跡（logEntryDeleted）を deletion-log に署名付きで残す', async () => {
    const { log } = await seeded(['vc-0', 'vc-1', 'vc-2']);

    await log.deleteEntriesForVc('vc-1', signer);

    const records = await log.listDeletionRecords();
    expect(records.map((r) => r.type)).toEqual(['logEntryDeleted']);
    expect(records[0]?.signature.split('.')).toHaveLength(3);
  });

  it('削除後も、証跡の無い別の欠損（攻撃者による削除）は sequenceGap として検知する', async () => {
    const { log, storage } = await seeded(['vc-0', 'vc-1', 'vc-2', 'vc-3']);
    await log.deleteEntriesForVc('vc-0', signer);
    await storage.delete('dashboard-log/000000000002');

    const result = await log.verify(verifierKey);

    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.reason)).toContain('sequenceGap');
  });

  it('対象が無ければ証跡も追記しない', async () => {
    const { log } = await seeded(['vc-0']);

    expect(await log.deleteEntriesForVc('missing', signer)).toBe(0);

    expect(await log.listDeletionRecords()).toEqual([]);
  });

  it('削除後の exportLog → importLog が成功し、取り込んだエントリが署名どおり残る', async () => {
    const { log } = await seeded(['vc-0', 'vc-1', 'vc-2']);
    await log.deleteEntriesForVc('vc-0', signer);
    await log.deleteEntriesForVc('vc-2', signer);
    const dest = new DashboardLog(new MemoryStorage());

    const imported = await dest.importLog(await log.exportLog(), verifierKey);

    expect(imported).toBe(1);
    expect((await dest.list()).map((e) => e.payload)).toEqual([{ vcId: 'vc-1', reason: 'r' }]);
  });
});

describe('CredentialStore.deleteCredential 後のログ検証', () => {
  it('deleteCredential 後も verify は ok で、export → import が成功する', async () => {
    const storage = new MemoryStorage();
    const log = new DashboardLog(storage, fixedNow('2026-10-01T00:00:00.000Z'));
    const store = new CredentialStore(storage, log);
    const vc = (id: string): VerifiableCredential => ({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:subject' },
      issuanceDate: '2026-01-01T00:00:00Z',
      id,
    });
    for (const id of ['vc-a', 'vc-b', 'vc-c']) {
      await store.store(vc(id));
      await log.append('correctionRequest', { vcId: id, reason: 'r' }, signer);
    }

    await store.deleteCredential('vc-b', signer);

    expect((await log.verify(verifierKey)).ok).toBe(true);
    const dest = new DashboardLog(new MemoryStorage());
    expect(await dest.importLog(await log.exportLog(), verifierKey)).toBe(2);
  });
});
