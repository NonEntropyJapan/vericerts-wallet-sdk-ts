/**
 * Dashboard ログの末尾（最新側）エントリ削除の検知。
 *
 * 末尾 N 件を storage から消しても連番・`prevHash` に穴は空かないため、修正前は `verify` が
 * `{ ok: true }` を返し、続く `append` が同じ連番で別内容を連結して履歴を巻き戻せた。
 * ログ本体とは別のキーに固定した末尾アンカーとの照合で検知する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import { DASHBOARD_LOG_TAIL_ANCHOR_KEY } from '../../dashboard-log/dashboard-log-shared.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

describe('DashboardLog 末尾削除の検知', () => {
  const signer = testSigner();
  const verifierKey: DashboardLogVerifierKey = {
    alg: signer.alg,
    publicKeyJwk: signer.publicKeyJwk,
  };
  const keyOf = (seq: number) => `dashboard-log/${String(seq).padStart(12, '0')}`;

  async function seeded(count: number): Promise<{ log: DashboardLog; storage: MemoryStorage }> {
    const storage = new MemoryStorage();
    const log = new DashboardLog(storage, fixedNow('2026-09-07T00:00:00.000Z'));
    for (let i = 0; i < count; i++) {
      await log.append('presentation', { clientId: `rp-${i}` }, signer);
    }
    return { log, storage };
  }

  it('末尾 1 件の削除を tailTruncated として報告する', async () => {
    const { log, storage } = await seeded(4);
    await storage.delete(keyOf(3));

    const result = await log.verify(verifierKey);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: '000000000003', reason: 'tailTruncated' }]);
  });

  it('末尾の複数件・全件の削除も検知する', async () => {
    const { log, storage } = await seeded(4);
    await storage.delete(keyOf(3));
    await storage.delete(keyOf(2));
    expect((await log.verify(verifierKey)).issues.map((i) => i.reason)).toEqual(['tailTruncated']);

    await storage.delete(keyOf(1));
    await storage.delete(keyOf(0));
    const empty = await log.verify(verifierKey);
    expect(empty.ok).toBe(false);
    expect(empty.issues.map((i) => i.reason)).toEqual(['tailTruncated']);
  });

  it('削除後の append で履歴を巻き戻しても、アンカーが据え置かれ検知が続く', async () => {
    const { log, storage } = await seeded(4);
    await storage.delete(keyOf(3));
    await storage.delete(keyOf(2));
    // 巻き戻した位置へ別内容を追記する（修正前はここで「最初からその履歴」の ok なログになった）。
    await log.append('presentation', { clientId: 'forged-2' }, signer);

    const afterOne = await log.verify(verifierKey);
    expect(afterOne.ok).toBe(false);

    // 連番がアンカーに追い付いて別内容のエントリが同じ連番を占めても、ハッシュ不一致で検知する。
    await log.append('presentation', { clientId: 'forged-3' }, signer);
    const afterTwo = await log.verify(verifierKey);
    expect(afterTwo.ok).toBe(false);
    expect(afterTwo.issues).toEqual([{ id: '000000000003', reason: 'tailTruncated' }]);

    // 一度検知されたログは、さらに追記を重ねても正常に戻らない。
    await log.append('presentation', { clientId: 'forged-4' }, signer);
    expect((await log.verify(verifierKey)).ok).toBe(false);
  });

  it('アンカーを壊す / 読めなくしても fail-closed で報告する（未導入に畳まない）', async () => {
    const { log, storage } = await seeded(2);
    await storage.set(DASHBOARD_LOG_TAIL_ANCHOR_KEY, new TextEncoder().encode('{"seq":"x"}'));

    const result = await log.verify(verifierKey);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: DASHBOARD_LOG_TAIL_ANCHOR_KEY, reason: 'tailTruncated' }]);
  });

  it('正当な経路（追記・個別削除・フィルタ削除・VC 削除・purge・インポート）では誤報しない', async () => {
    const { log, storage } = await seeded(3);
    expect((await log.verify(verifierKey)).ok).toBe(true);

    // 末尾エントリの個別削除（Art.17）は削除証跡が説明する。アンカーは残存末尾へ移る。
    expect(await log.deleteLogEntry('000000000002', signer)).toBe(true);
    expect((await log.verify(verifierKey)).ok).toBe(true);

    // 削除後の追記も連続して正常。
    await log.append('presentation', { clientId: 'rp-after' }, signer);
    expect((await log.verify(verifierKey)).ok).toBe(true);

    // フィルタ削除で末尾を消す。
    await log.deleteLogEntries(undefined, signer);
    expect((await log.verify(verifierKey)).ok).toBe(true);
    expect(await storage.get(DASHBOARD_LOG_TAIL_ANCHOR_KEY)).toBeNull();

    // 全消去後は新しい連鎖として正常に始められる。
    await log.append('presentation', { clientId: 'rp-fresh' }, signer);
    expect((await log.verify(verifierKey)).ok).toBe(true);

    // エクスポート → 別 storage へインポートしても、取り込んだ末尾がアンカーになり正常。
    const other = new DashboardLog(new MemoryStorage(), fixedNow('2026-09-07T00:00:00.000Z'));
    await other.importLog(await log.exportLog(), verifierKey);
    expect((await other.verify(verifierKey)).ok).toBe(true);
  });

  it('アンカー導入前のログ（アンカー未保存）は検証対象外で、次の追記から追従する', async () => {
    const { log, storage } = await seeded(3);
    await storage.delete(DASHBOARD_LOG_TAIL_ANCHOR_KEY);
    expect((await log.verify(verifierKey)).ok).toBe(true);

    await log.append('presentation', { clientId: 'rp-3' }, signer);
    await storage.delete(keyOf(3));
    expect((await log.verify(verifierKey)).issues.map((i) => i.reason)).toEqual(['tailTruncated']);
  });

  it('アンカーキーは list(prefix) にエントリとして現れない', async () => {
    const { log, storage } = await seeded(2);

    expect(await storage.list('dashboard-log/')).toHaveLength(2);
    expect(await storage.list('deletion-log/')).toHaveLength(0);
    expect(await storage.get(DASHBOARD_LOG_TAIL_ANCHOR_KEY)).not.toBeNull();
    expect((await log.list()).map((entry) => entry.id)).toEqual(['000000000000', '000000000001']);
  });
});
