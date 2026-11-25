/**
 * 復号不能（破損）な `dashboard-log/` エントリが混在しても Art.17 削除経路が止まらないことの回帰テスト
 *
 * 以前は `deleteEntriesForVc` / `purgeEntries` が `decodeDashboardLogEntry` の 6005 を伝播して全体を中断し、
 * `deleteCredential` は VC を残したまま削除監査記録（`credentialDeleted`）だけを呼び出しのたびに積み増した。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import type { VerifiableCredential } from '../../../credential/index.js';
import { CredentialStore } from '../../credential-store/index.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { logPresentationEvent } from '../../presentation-log.js';
import { testSigner } from '../dashboard-log/dashboard-log-helpers.js';

const CORRUPT_KEY = 'dashboard-log/000000000000';

function makeVc(id: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id,
  };
}

/** 正常エントリを追記したうえで、先頭（連番 0）を復号不能なバイト列に差し替える。 */
async function setup(...credentialIdsPerEntry: string[][]) {
  const storage = new MemoryStorage();
  const dashboardLog = new DashboardLog(storage);
  const store = new CredentialStore(storage, dashboardLog);
  for (const credentialIds of [['corrupted-later'], ...credentialIdsPerEntry]) {
    await logPresentationEvent({
      log: dashboardLog,
      signer: testSigner(),
      clientId: 'https://rp.example',
      credentialIds,
    });
  }
  await storage.set(CORRUPT_KEY, Uint8Array.of(1, 2, 3));
  return { storage, dashboardLog, store };
}

describe('破損 dashboard-log エントリ混在時の Art.17 削除', () => {
  it('deleteCredential は破損エントリを読み飛ばして VC と参照エントリを削除し、監査記録は 1 件だけ', async () => {
    const { storage, dashboardLog, store } = await setup(['vc-1'], ['vc-2']);
    await store.store(makeVc('vc-1'));

    await store.deleteCredential('vc-1', testSigner());

    expect(await store.get('vc-1')).toBeNull();
    expect(await storage.get('dashboard-log/000000000001')).toBeNull();
    expect(await storage.get('dashboard-log/000000000002')).not.toBeNull();
    // 破損エントリ自体は参照判定できないので残す（verify が undecodable として報告する）。
    expect(await storage.get(CORRUPT_KEY)).not.toBeNull();
    // 監査記録（credentialDeleted）は 1 件だけ。他に削除証跡（logEntryDeleted）が 1 件付く。
    const records = await dashboardLog.listDeletionRecords();
    expect(records.map((r) => r.type)).toEqual(['credentialDeleted', 'logEntryDeleted']);
  });

  it('purgeDashboardLog（フィルタなし）は破損エントリも含めて全件削除する', async () => {
    const { storage, store } = await setup(['vc-1'], ['vc-2']);

    const deleted = await store.purgeDashboardLog();

    expect(deleted).toBe(3);
    expect(await storage.list('dashboard-log/')).toEqual([]);
  });

  it('purgeDashboardLog（フィルタあり）は破損エントリを残し、破損より後ろの一致エントリを削除する', async () => {
    const { storage, store } = await setup(['vc-1'], ['vc-2']);

    const deleted = await store.purgeDashboardLog({ types: ['presentation'] });

    expect(deleted).toBe(2);
    expect(await storage.list('dashboard-log/')).toEqual([CORRUPT_KEY]);
  });

  it('破損以外の例外（storage.get の失敗）は握り潰さず伝播する', async () => {
    const { storage } = await setup(['vc-1']);
    const failing = {
      get: () => Promise.reject(new Error('io down')),
      set: (k: string, v: Uint8Array) => storage.set(k, v),
      delete: (k: string) => storage.delete(k),
      list: (p: string) => storage.list(p),
    };
    const failingStore = new CredentialStore(storage, new DashboardLog(failing));

    await expect(failingStore.purgeDashboardLog()).rejects.toThrow('io down');
  });
});
