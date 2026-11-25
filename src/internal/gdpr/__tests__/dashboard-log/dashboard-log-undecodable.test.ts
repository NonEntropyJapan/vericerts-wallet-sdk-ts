/**
 * 破損エントリ（復号不能）に対する `DashboardLog` の振る舞いの単体テスト。
 *
 * Dashboard が破損を利用者に知らせられるよう、`verify`
 * だけが破損を許容して `undecodable` としてレポートし、`list` / `append` は厳格なまま `6005`
 * （`STORAGE_RECORD_CORRUPTED`。従来は VC 専用の `3070` を流用していた）を投げる
 * （破損を「不在」に畳むと追記が壊れ、先頭破損が正当な切り捨てに化ける）。その境界の回帰テスト。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { ErrorCodes } from '../../../errors.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import type { DashboardLogVerifierKey } from '../../dashboard-log/dashboard-log-import.js';
import type { DashboardLogStorage } from '../../dashboard-log/dashboard-log-shared.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

describe('DashboardLog と破損エントリ', () => {
  const keyOf = (seq: number) => `dashboard-log/${String(seq).padStart(12, '0')}`;
  const idOf = (seq: number) => keyOf(seq).slice(-12);

  const signer = testSigner();
  const verifierKey: DashboardLogVerifierKey = {
    alg: signer.alg,
    publicKeyJwk: signer.publicKeyJwk,
  };

  /** エントリ `count` 件を追記したログを返す。 */
  async function seeded(count: number): Promise<{ log: DashboardLog; storage: MemoryStorage }> {
    const storage = new MemoryStorage();
    const log = new DashboardLog(storage, fixedNow('2026-09-07T00:00:00.000Z'));
    for (let i = 0; i < count; i++) {
      await log.append('presentation', { clientId: `rp-${i}` }, signer);
    }
    return { log, storage };
  }

  /** 保存済みエントリを JSON として読めないバイト列に差し替える。 */
  async function corrupt(storage: MemoryStorage, seq: number): Promise<void> {
    await storage.set(keyOf(seq), new TextEncoder().encode('{ not json'));
  }

  it('list は破損エントリで 6005 を投げる（破損を不在に畳まない）', async () => {
    const { log, storage } = await seeded(3);
    await corrupt(storage, 1);

    await expect(log.list()).rejects.toMatchObject({
      code: ErrorCodes.STORAGE_RECORD_CORRUPTED,
    });
  });

  it('verify は破損エントリを undecodable として報告し、例外を投げない', async () => {
    const { log, storage } = await seeded(3);
    await corrupt(storage, 1);

    const result = await log.verify(verifierKey);

    expect(result.ok).toBe(false);
    // 破損そのものと、chain から抜けたことによる直後の欠損の両方を追記順で報告する。
    expect(result.issues).toEqual([
      { id: idOf(1), reason: 'undecodable' },
      { id: idOf(2), reason: 'sequenceGap' },
    ]);
    // 復号できた 2 件だけを検証対象として数える。
    expect(result.count).toBe(2);
  });

  it('先頭（連番 0）の破損を正当な切り捨てとして見逃さない', async () => {
    const { log, storage } = await seeded(3);
    await corrupt(storage, 0);

    const result = await log.verify(verifierKey);

    // 先頭が欠けた見た目は保持上限による切り捨てと同じだが、破損は必ず ok を落として報告する。
    expect(result.ok).toBe(false);
    expect(result.issues).toContainEqual({ id: idOf(0), reason: 'undecodable' });
  });

  it('末尾の破損でも検証は完走し、追記だけが失敗する', async () => {
    const { log, storage } = await seeded(3);
    await corrupt(storage, 2);

    const result = await log.verify(verifierKey);

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual([{ id: idOf(2), reason: 'undecodable' }]);
    // prevHash を末尾から計算できないため、追記は静かに続行せず失敗する（chain 分岐を作らない）。
    await expect(log.append('presentation', { clientId: 'rp-3' }, signer)).rejects.toMatchObject({
      code: ErrorCodes.STORAGE_RECORD_CORRUPTED,
    });
  });

  it('storage.get 自体が例外を投げる破損も undecodable として報告する', async () => {
    const { storage } = await seeded(2);
    // 組込先（extension の base64 破損）のように、読み出し時点で例外になる storage を模す。
    const failing: DashboardLogStorage = {
      get: (key) => {
        if (key === keyOf(0)) throw new Error('corrupted record');
        return storage.get(key);
      },
      set: (key, value) => storage.set(key, value),
      delete: (key) => storage.delete(key),
      list: (prefix) => storage.list(prefix),
    };

    const result = await new DashboardLog(failing).verify(verifierKey);

    expect(result.ok).toBe(false);
    expect(result.issues).toContainEqual({ id: idOf(0), reason: 'undecodable' });
  });
});
