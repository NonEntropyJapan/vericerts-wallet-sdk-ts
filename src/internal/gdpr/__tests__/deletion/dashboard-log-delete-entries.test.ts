/**
 * `DashboardLog.deleteLogEntry` / `deleteLogEntries`（Art.17 個別 / フィルタ削除）の回帰テスト。
 *
 * 切り捨てウォーターマークと同じ発想で、削除記録（`logEntryDeleted`、`deletion-log/` へ JWS
 * 署名付きで追記）と矛盾なく説明できる欠損は `verifyDashboardLogChain` が `sequenceGap` から除外する。
 * 削除記録を伴わない欠損（= 攻撃者によるセクション削除）は従来どおり検知され続けることも確認する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { encodeDashboardLogEntry } from '../../codec.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import type { DashboardLogTrimWatermark } from '../../log-integrity/chain.js';
import type { DashboardLogEntry } from '../../types.js';
import {
  createPrivateKeySignerFromFill,
  fixedNow,
  testSigner,
} from '../dashboard-log/dashboard-log-helpers.js';

describe('DashboardLog.deleteLogEntry / deleteLogEntries', () => {
  function verifierKeyOf(signer: ReturnType<typeof testSigner>): DashboardLogVerifierKey {
    return { alg: signer.alg, publicKeyJwk: signer.publicKeyJwk };
  }

  async function seeded(count: number): Promise<{
    log: DashboardLog;
    storage: MemoryStorage;
    signer: ReturnType<typeof testSigner>;
  }> {
    const storage = new MemoryStorage();
    const signer = testSigner();
    const log = new DashboardLog(storage, fixedNow('2026-09-16T00:00:00.000Z'));
    for (let i = 0; i < count; i++) {
      await log.append('presentation', { clientId: `rp-${i}` }, signer);
    }
    return { log, storage, signer };
  }

  const keyOf = (seq: number) => `dashboard-log/${String(seq).padStart(12, '0')}`;

  it('個別削除（deleteLogEntry）した中間エントリは sequenceGap を出さない', async () => {
    const { log, signer } = await seeded(5);

    const deleted = await log.deleteLogEntry(keyOf(2).slice(-12), signer);
    expect(deleted).toBe(true);

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.count).toBe(4);
  });

  it('存在しない ID を指定すると false を返し、chain は変化しない', async () => {
    const { log, signer } = await seeded(3);

    const deleted = await log.deleteLogEntry('does-not-exist', signer);

    expect(deleted).toBe(false);
    const result = await log.verify(verifierKeyOf(signer));
    expect(result.ok).toBe(true);
    expect(result.count).toBe(3);
  });

  it('フィルタ削除（deleteLogEntries）で複数の非連続エントリを削除しても sequenceGap を出さない', async () => {
    const storage = new MemoryStorage();
    const signer = testSigner();
    const log = new DashboardLog(storage, fixedNow('2026-09-16T00:00:00.000Z'));
    // types で絞り込める非連続な削除対象を作る（seq 1 と seq 3 だけ 'correctionRequest'）。
    await log.append('presentation', { clientId: 'rp-0' }, signer);
    await log.append('correctionRequest', { vcId: 'vc-1', reason: 'typo' }, signer);
    await log.append('presentation', { clientId: 'rp-2' }, signer);
    await log.append('correctionRequest', { vcId: 'vc-2', reason: 'typo' }, signer);
    await log.append('presentation', { clientId: 'rp-4' }, signer);

    const deletedCount = await log.deleteLogEntries({ types: ['correctionRequest'] }, signer);
    expect(deletedCount).toBe(2);

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.count).toBe(3);
  });

  it('先頭側の連番をまとめて削除しても sequenceGap を出さない（トリム透かしとは独立の経路）', async () => {
    const storage = new MemoryStorage();
    const signer = testSigner();
    // 1 件ごとに時刻を進める（olderThan で先頭 3 件だけを狙い撃ちするため）。
    let tick = 0;
    const log = new DashboardLog(storage, () => new Date(Date.UTC(2026, 8, 16, 0, 0, tick++)));
    for (let i = 0; i < 5; i++) {
      await log.append('presentation', { clientId: `rp-${i}` }, signer);
    }

    // seq 0〜2（recordedAt 00:00:00〜00:00:02）だけが対象、seq 3〜4 は残す。
    const deletedCount = await log.deleteLogEntries(
      { olderThan: '2026-09-16T00:00:03.000Z' },
      signer,
    );
    expect(deletedCount).toBe(3);

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.count).toBe(2);
  });

  it('watermark（trim）済みログの残存先頭をさらに削除しても sequenceGap を出さない', async () => {
    // 先頭エントリの整合性判定が「ウォーターマーク照合」と
    // 「削除証跡での説明」の排他的な if-else になっており、削除区間の起点を常に chain 起点（seq 0 /
    // prevHash null）に固定していたため、「trim済み（watermarkあり）→残存先頭を削除」の順で操作すると
    // 削除証跡照合が `resolveDeletionSpan(0, seq, null, ...)` を試みて seq 0 の証跡が無い（trim された
    // だけで削除証跡は無い）ため `undefined` となり、恒久的な `sequenceGap` が報告されていた。
    const { log, storage, signer } = await seeded(5);

    // 保持上限による trim: seq 0 を切り捨てて watermark を作る（本番の trim() と同じ導出。
    // 残存先頭 seq 1 の prevHash が定義上「最後に切り捨てたエントリの signing-input ハッシュ」）。
    const rawSeq1 = (await storage.get(keyOf(1))) as Uint8Array;
    const entrySeq1 = JSON.parse(new TextDecoder().decode(rawSeq1)) as DashboardLogEntry;
    const watermark: DashboardLogTrimWatermark = { seq: 0, prevHash: entrySeq1.prevHash as string };
    await storage.delete(keyOf(0));

    // trim 後の残存先頭（seq 1）を正規の deleteLogEntry でユーザー操作により削除する（削除記録あり）。
    const deleted = await log.deleteLogEntry(keyOf(1).slice(-12), signer);
    expect(deleted).toBe(true);

    const result = await log.verify(verifierKeyOf(signer), watermark);

    expect(result.ok).toBe(true);
    expect(result.truncated).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.count).toBe(3);
  });

  it('削除記録を伴わない欠損（攻撃者によるセクション削除）は引き続き sequenceGap として検知する', async () => {
    const { log, storage, signer } = await seeded(5);
    // 監査記録を残さず storage から直接消す。
    await storage.delete(keyOf(2));

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: keyOf(3).slice(-12), reason: 'sequenceGap' }]);
  });

  it('正当な削除記録がある欠損に攻撃者が別のエントリも巻き込んで消すと sequenceGap を検知する', async () => {
    const { log, storage, signer } = await seeded(5);
    // seq 2 は正規の deleteLogEntry で消す（削除記録あり）。
    await log.deleteLogEntry(keyOf(2).slice(-12), signer);
    // 攻撃者が隣接する seq 1 も削除記録なしで追加削除する。
    await storage.delete(keyOf(1));

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.issues.some((issue) => issue.reason === 'sequenceGap')).toBe(true);
  });

  it('連番が巨大に飛んだ欠損でも即座に sequenceGap として検知する（deletionRecords が空なら初回反復で打ち切られる）', async () => {
    const { log, storage, signer } = await seeded(2);
    // storage を直接改ざんし、seq 1 を巨大な連番（12 桁の最大値）へ付け替える。
    // id は署名対象外。resolveDeletionSpan は deletionRecords に対応する
    // 記録が無い最初の連番で即座に打ち切るため、ギャップの大きさに関わらず高速に終わる。
    const raw = (await storage.get(keyOf(1))) as Uint8Array;
    const entry = JSON.parse(new TextDecoder().decode(raw)) as DashboardLogEntry;
    const hugeId = '999999999999';
    await storage.delete(keyOf(1));
    await storage.set(`dashboard-log/${hugeId}`, encodeDashboardLogEntry({ ...entry, id: hugeId }));

    const started = Date.now();
    const result = await log.verify(verifierKeyOf(signer));
    const elapsedMs = Date.now() - started;

    expect(elapsedMs).toBeLessThan(2000);
    expect(result.ok).toBe(false);
    expect(result.issues.some((issue) => issue.reason === 'sequenceGap')).toBe(true);
  });

  it('別鍵で署名された削除記録（偽造）は信用されず sequenceGap のまま検知する', async () => {
    const { log, signer } = await seeded(5);
    // 攻撃者が K4 ブロブへの書込権限は持つが Dashboard ログ専用鍵は持たない、という想定:
    // deleteLogEntry 自体は正規の経路を通すが、削除記録に署名する鍵だけを別物にする。
    const attacker = createPrivateKeySignerFromFill(99);

    const deleted = await log.deleteLogEntry(keyOf(2).slice(-12), attacker);
    expect(deleted).toBe(true);

    // 検証は本来の（正規の）検証鍵で行う。偽造記録の署名はこの鍵での検証に失敗するため無視される。
    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.issues.some((issue) => issue.reason === 'sequenceGap')).toBe(true);
  });
});
