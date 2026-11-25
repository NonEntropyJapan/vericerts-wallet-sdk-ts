/**
 * DashboardLog の並行 `append`。list → 採番 → 署名(await) → set が直列化されず、
 * 同一連番で互いを上書きして監査エントリが消失していた回帰を防ぐ。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { signingInputHash } from '../../dashboard-log/dashboard-log-shared.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

describe('DashboardLog 並行 append', () => {
  it('Promise.all の並行 append が全件保存され、連番と prevHash chain を維持する', async () => {
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));
    const signer = testSigner();

    const appended = await Promise.all(
      [0, 1, 2, 3].map((n) => log.append('correctionRequest', { n }, signer)),
    );

    expect(appended.map((e) => e.id)).toEqual([
      '000000000000',
      '000000000001',
      '000000000002',
      '000000000003',
    ]);
    const stored = await log.list();
    expect(stored).toHaveLength(4);
    expect(stored[0]?.prevHash).toBeNull();
    for (let i = 1; i < stored.length; i++) {
      expect(stored[i]?.prevHash).toBe(signingInputHash(stored[i - 1] as never));
    }
  });

  it('削除監査記録（deletion-log）への並行追記も欠落しない', async () => {
    const log = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));
    const signer = testSigner();

    await Promise.all(['vc-1', 'vc-2', 'vc-3'].map((id) => log.appendDeletionRecord(id, signer)));

    const records = await log.listDeletionRecords();
    expect(records.map((r) => r.payload.vcId).sort()).toEqual(['vc-1', 'vc-2', 'vc-3']);
  });
});
