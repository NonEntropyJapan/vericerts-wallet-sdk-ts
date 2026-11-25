/**
 * DashboardLog.verify / verifyDashboardLogChain（保存済みログの改ざん・欠損検知）の単体テスト。
 *
 * 保存済みエントリの署名・ハッシュの連鎖・連番を検査し、改ざんや欠損が
 * 該当するエントリとともにレポートされることを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { encodeDashboardLogEntry } from '../../codec.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import type { DashboardLogTrimWatermark } from '../../log-integrity/chain.js';
import type { DashboardLogEntry } from '../../types.js';
import { createPrivateKeySignerFromFill, fixedNow, testSigner } from './dashboard-log-helpers.js';

describe('DashboardLog verify', () => {
  function verifierKeyOf(signer: ReturnType<typeof testSigner>): DashboardLogVerifierKey {
    return { alg: signer.alg, publicKeyJwk: signer.publicKeyJwk };
  }

  /** エントリ `count` 件を追記したログと storage / signer を返す。 */
  async function seeded(count: number): Promise<{
    log: DashboardLog;
    storage: MemoryStorage;
    signer: ReturnType<typeof testSigner>;
  }> {
    const storage = new MemoryStorage();
    const signer = testSigner();
    const log = new DashboardLog(storage, fixedNow('2026-09-07T00:00:00.000Z'));
    for (let i = 0; i < count; i++) {
      await log.append('presentation', { clientId: `rp-${i}` }, signer);
    }
    return { log, storage, signer };
  }

  const keyOf = (seq: number) => `dashboard-log/${String(seq).padStart(12, '0')}`;

  /** storage 上の 1 エントリを書き換える。 */
  async function overwrite(
    storage: MemoryStorage,
    seq: number,
    mutate: (entry: DashboardLogEntry) => DashboardLogEntry,
  ): Promise<void> {
    const raw = await storage.get(keyOf(seq));
    const entry = JSON.parse(new TextDecoder().decode(raw as Uint8Array)) as DashboardLogEntry;
    await storage.set(keyOf(seq), encodeDashboardLogEntry(mutate(entry)));
  }

  it('改ざんのないログは ok で、merkleRoot が exportLog のルートハッシュと一致する', async () => {
    const { log, signer } = await seeded(3);

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.count).toBe(3);
    expect(result.truncated).toBe(false);
    // exportLog の末尾ルートハッシュ行と同一計算であることを突き合わせる。
    const rootLine = (await log.exportLog()).split('\n').at(-1) as string;
    expect(JSON.parse(rootLine)).toEqual({ merkleRoot: result.merkleRoot, count: 3 });
  });

  it('空ログは ok・0 件・merkleRoot null を返す', async () => {
    const { log, signer } = await seeded(0);

    const result = await log.verify(verifierKeyOf(signer));

    expect(result).toEqual({ ok: true, count: 0, truncated: false, merkleRoot: null, issues: [] });
  });

  it('payload を書き換えると当該エントリを signatureInvalid として検知する', async () => {
    const { log, storage, signer } = await seeded(3);
    // 署名は据え置いて本文だけ差し替える（署名対象 payload と本文の不一致）。
    await overwrite(storage, 1, (entry) => ({
      ...entry,
      payload: { clientId: 'attacker.example' },
    }));

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: keyOf(1).slice(-12), reason: 'signatureInvalid' }]);
  });

  it('中間エントリを削除すると sequenceGap として欠損を検知する', async () => {
    const { log, storage, signer } = await seeded(3);
    // 監査ログのセクション削除: 中間の 1 件だけを storage から消す。
    await storage.delete(keyOf(1));

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.count).toBe(2);
    // 穴の直後のエントリで欠損を報告する。切り捨て（truncated）とは区別される。
    expect(result.issues).toEqual([{ id: keyOf(2).slice(-12), reason: 'sequenceGap' }]);
    expect(result.truncated).toBe(false);
  });

  it('prevHash を書き換えると chainBroken と signatureInvalid の両方を検知する', async () => {
    const { log, storage, signer } = await seeded(3);
    // prevHash は署名対象にも含まれるため、chain 断絶と署名不一致の両方が立つ。
    await overwrite(storage, 2, (entry) => ({ ...entry, prevHash: 'AAAA' }));

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.issues.map((i) => i.reason).sort()).toEqual(['chainBroken', 'signatureInvalid']);
  });

  it('先頭エントリの prevHash が null でなければ chainBroken を検知する', async () => {
    const { log, storage, signer } = await seeded(2);
    await overwrite(storage, 0, (entry) => ({ ...entry, prevHash: 'AAAA' }));

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.issues.some((i) => i.reason === 'chainBroken')).toBe(true);
    expect(result.truncated).toBe(false);
  });

  /**
   * 連番 `seq` のエントリが「残存先頭」になったときのウォーターマークを組む。
   *
   * 残存先頭の `prevHash` は定義上「直前（= 最後に切り捨てた）エントリの signing-input ハッシュ」なので、
   * ハッシュを計算せずに組める（本番の `trim()` と同じ導出）。
   */
  async function watermarkFor(
    storage: MemoryStorage,
    seq: number,
  ): Promise<DashboardLogTrimWatermark> {
    const raw = (await storage.get(keyOf(seq))) as Uint8Array;
    const entry = JSON.parse(new TextDecoder().decode(raw)) as DashboardLogEntry;
    return { seq: seq - 1, prevHash: entry.prevHash as string };
  }

  it('保持上限による先頭の切り捨てはウォーターマークと一致すれば truncated として ok を保つ', async () => {
    const { log, storage, signer } = await seeded(3);
    // 古い順に捨てる保持上限の再現（先頭の連番が 0 でなくなる）。
    const watermark = await watermarkFor(storage, 1);
    await storage.delete(keyOf(0));

    const result = await log.verify(verifierKeyOf(signer), watermark);

    expect(result.ok).toBe(true);
    expect(result.truncated).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.count).toBe(2);
  });

  it('ウォーターマーク無しで先頭の連番が 0 でなければ sequenceGap を検知する', async () => {
    const { log, storage, signer } = await seeded(3);
    await storage.delete(keyOf(0));

    // 切り捨てを記録していないのに前方が無い = 先頭ごと削除された疑い。truncated へ逃がさない。
    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.truncated).toBe(false);
    expect(result.issues).toEqual([{ id: keyOf(1).slice(-12), reason: 'sequenceGap' }]);
  });

  it('隠したいエントリを前方ごと削除しても検知する（truncated 経路の悪用）', async () => {
    // 修正前の挙動: seq 0〜2 を消すと先頭が seq 3 になり「先頭の連番が 0 でない = 正当な切り捨て」と
    // 判定され、`{ ok: true, truncated: true, issues: [] }` を返して seq 2 の削除が素通りしていた。
    const { log, storage, signer } = await seeded(5);
    // seq 2 を隠すため、それより前（seq 0, 1）も一緒に消す。連番に穴は空かない。
    for (const seq of [0, 1, 2]) await storage.delete(keyOf(seq));

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    expect(result.truncated).toBe(false);
    expect(result.issues).toEqual([{ id: keyOf(3).slice(-12), reason: 'sequenceGap' }]);
  });

  it('ウォーターマークが残存先頭と一致しなければ sequenceGap を検知する', async () => {
    const { log, storage, signer } = await seeded(5);
    // seq 0 までしか切り捨てていない記録を残したうえで、seq 1〜2 を追加で削除する
    // （正当な切り捨てを装った先頭ごとの削除）。
    const stale = await watermarkFor(storage, 1);
    for (const seq of [0, 1, 2]) await storage.delete(keyOf(seq));

    const result = await log.verify(verifierKeyOf(signer), stale);

    expect(result.ok).toBe(false);
    expect(result.truncated).toBe(false);
    expect(result.issues).toEqual([{ id: keyOf(3).slice(-12), reason: 'sequenceGap' }]);
  });

  it('連番が合っていても prevHash が一致しなければ sequenceGap を検知する', async () => {
    const { log, storage, signer } = await seeded(3);
    await storage.delete(keyOf(0));
    // `entry.id` は署名対象外なので連番だけなら偽装できる。担保は prevHash の一致である。
    const forged: DashboardLogTrimWatermark = { seq: 0, prevHash: 'AAAA' };

    const result = await log.verify(verifierKeyOf(signer), forged);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: keyOf(1).slice(-12), reason: 'sequenceGap' }]);
  });

  it('別の鍵で検証すると全エントリを signatureInvalid として検知する', async () => {
    const { log } = await seeded(2);
    const other = createPrivateKeySignerFromFill(9);

    const result = await log.verify(verifierKeyOf(other));

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([
      { id: keyOf(0).slice(-12), reason: 'signatureInvalid' },
      { id: keyOf(1).slice(-12), reason: 'signatureInvalid' },
    ]);
  });

  it('連番として読めない ID は malformedId として検知する', async () => {
    const { log, storage, signer } = await seeded(1);
    const raw = (await storage.get(keyOf(0))) as Uint8Array;
    const entry = JSON.parse(new TextDecoder().decode(raw)) as DashboardLogEntry;
    await storage.delete(keyOf(0));
    // storage キーは連番形のまま、エントリ本文の id だけを壊す（storage 破損の再現）。
    await storage.set(keyOf(0), encodeDashboardLogEntry({ ...entry, id: 'not-a-sequence' }));

    const result = await log.verify(verifierKeyOf(signer));

    expect(result.ok).toBe(false);
    // `id` は署名対象 payload（type / payload / recordedAt / prevHash）に含まれないため署名は有効なまま。
    // それでも連番が読めなければ chain の順序を確認できないので破損として報告する。
    expect(result.issues).toEqual([{ id: 'not-a-sequence', reason: 'malformedId' }]);
  });
});
