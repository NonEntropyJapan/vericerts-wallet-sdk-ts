/**
 * LogFilter.olderThan の厳格な日時比較。ISO 文字列の辞書順比較では、不正値が全件に一致して
 * purgeDashboardLog（不可逆）が全件削除になり、オフセット付き・ミリ秒なし表記で境界が狂っていた。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

/** 指定時刻に 1 件ずつ追記した（2026-09-01T03:00:00Z / 2026-09-01T00:00:00.500Z）ログを作る。 */
async function seededLog(): Promise<DashboardLog> {
  const signer = testSigner();
  const storage = new MemoryStorage();
  const times = ['2026-09-01T00:00:00.500Z', '2026-09-01T03:00:00.000Z'];
  let log = new DashboardLog(storage);
  for (const [i, time] of times.entries()) {
    log = new DashboardLog(storage, fixedNow(time));
    await log.append('correctionRequest', { vcId: `vc-${i}`, reason: 'x' }, signer);
  }
  return log;
}

const vcIds = async (log: DashboardLog): Promise<string[]> =>
  (await log.list()).map((e) => (e.payload as { vcId: string }).vcId);

describe('LogFilter.olderThan の検証', () => {
  it.each([
    'yesterday',
    'not-a-date',
    '',
    '2026-09-01',
    '2026-09-01T00:00:00',
    '2026-02-30T00:00:00Z',
  ])('不正値 %p は purge / exportLog / deleteLogEntries で拒否し、何も削除しない', async (olderThan) => {
    const log = await seededLog();
    const signer = testSigner();

    await expect(log.purge({ olderThan })).rejects.toMatchObject({ code: '3002' });
    await expect(log.exportLog({ olderThan })).rejects.toMatchObject({ code: '3002' });
    await expect(log.deleteLogEntries({ olderThan }, signer)).rejects.toMatchObject({
      code: '3002',
    });
    expect(await vcIds(log)).toEqual(['vc-0', 'vc-1']);
  });

  it('オフセット付き olderThan は UTC に正規化して比較する（+09:00 の 09:00 = 00:00Z）', async () => {
    const log = await seededLog();

    // 辞書順では '03:00' < '09:00' で vc-1 も削除されていた。実際は 00:00:00.500Z のみが前。
    const deleted = await log.purge({ olderThan: '2026-09-01T09:00:00+09:00' });

    expect(deleted).toBe(0);
    expect(await vcIds(log)).toEqual(['vc-0', 'vc-1']);
  });

  it('ミリ秒なし olderThan でもサブ秒の境界を正しく判定する', async () => {
    const log = await seededLog();

    // 辞書順では '.' < 'Z' で 00:00:00.500Z が「00:00:00Z より前」と誤判定されていた。
    expect(await log.purge({ olderThan: '2026-09-01T00:00:00Z' })).toBe(0);
    expect(await log.purge({ olderThan: '2026-09-01T00:00:01Z' })).toBe(1);
    expect(await vcIds(log)).toEqual(['vc-1']);
  });

  it('exportLog の olderThan もオフセット付き表記を正規化して絞り込む', async () => {
    const log = await seededLog();

    const lines = (await log.exportLog({ olderThan: '2026-09-01T12:00:00+09:00' })).split('\n');

    // 12:00+09:00 = 03:00:00Z。< なので 03:00:00.000Z 自身は含まれず、エントリ 1 件 + ルート行。
    expect(lines).toHaveLength(2);
  });
});
