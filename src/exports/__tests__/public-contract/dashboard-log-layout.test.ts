/**
 * Dashboard ログの保存 layout とエクスポート MIME の公開契約。`@vericerts/vericerts-wallet-sdk/gdpr` から
 * 引いた公開面だけで、組込先が `DashboardLogStorage` の保存先を直接読み書きするときに頼るキーの形を固定する。
 * 内部パス経由では「公開したつもりの面」が通っているかを確かめられないので `../../gdpr.js` を使う。
 */

import { describe, expect, test } from 'bun:test';
import { createPrivateKeySigner } from '../../credential.js';
import {
  DASHBOARD_LOG_EXPORT_MIME,
  DASHBOARD_LOG_KEY_PREFIX,
  DASHBOARD_LOG_TAIL_ANCHOR_KEY,
  DashboardLog,
  type DashboardLogStorage,
  logPresentationEvent,
  PRESENTATION_LOG_TYPE,
} from '../../gdpr.js';

const SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256K');

/**
 * 組込先の storage を模した最小の Map 実装。`list` は順序を規定しない契約なので、prefix 一致のキーを
 * 挿入の逆順で返し、呼び出し側が順序に頼っていないことを確かめる。
 */
function mapStorage(): DashboardLogStorage & { keys(): string[] } {
  const map = new Map<string, Uint8Array>();
  return {
    get: async (key) => map.get(key) ?? null,
    set: async (key, value) => {
      map.set(key, value);
    },
    delete: async (key) => {
      map.delete(key);
    },
    list: async (prefix) => [...map.keys()].filter((key) => key.startsWith(prefix)).reverse(),
    keys: () => [...map.keys()],
  };
}

async function logWithTwoPresentations() {
  const storage = mapStorage();
  const log = new DashboardLog(storage);
  for (const clientId of ['https://a.example', 'https://b.example']) {
    await logPresentationEvent({ log, signer: SIGNER, clientId });
  }
  return { storage, log };
}

describe('Dashboard ログの保存 layout', () => {
  test('4 定数の値を固定する', () => {
    expect(DASHBOARD_LOG_EXPORT_MIME).toBe('application/x-ndjson');
    expect(PRESENTATION_LOG_TYPE).toBe('presentation');
    expect(DASHBOARD_LOG_KEY_PREFIX).toBe('dashboard-log/');
    expect(DASHBOARD_LOG_TAIL_ANCHOR_KEY).toBe('anchor/dashboard-log');
  });

  test('エントリは prefix + id に、末尾アンカーは prefix 外の固定キーに保存される', async () => {
    const { storage, log } = await logWithTwoPresentations();
    const entries = await log.list();
    expect(entries).toHaveLength(2);

    const entryKeys = (await storage.list(DASHBOARD_LOG_KEY_PREFIX)).sort();
    expect(entryKeys).toEqual(entries.map((entry) => `${DASHBOARD_LOG_KEY_PREFIX}${entry.id}`));
    expect(entryKeys).not.toContain(DASHBOARD_LOG_TAIL_ANCHOR_KEY);
    for (const key of storage.keys()) {
      expect(
        key.startsWith(DASHBOARD_LOG_KEY_PREFIX) || key === DASHBOARD_LOG_TAIL_ANCHOR_KEY,
      ).toBe(true);
    }

    expect(await storage.get(DASHBOARD_LOG_TAIL_ANCHOR_KEY)).not.toBeNull();
  });

  test('提示イベントのエントリ種別は PRESENTATION_LOG_TYPE である', async () => {
    const { log } = await logWithTwoPresentations();
    for (const entry of await log.list()) {
      expect(entry.type).toBe(PRESENTATION_LOG_TYPE);
    }
  });

  test('同じ storage に作り直したインスタンスが既存ログを読み、署名チェーンを続けて追記する', async () => {
    const { storage, log } = await logWithTwoPresentations();
    const before = await log.list();

    // 組込先の再起動（Service Worker の再生成など）と同じく、保存先だけを引き継いで作り直す。
    const reloaded = new DashboardLog(storage);
    const pick = (entries: typeof before) => entries.map(({ id, type }) => ({ id, type }));
    expect(pick(await reloaded.list())).toEqual(pick(before));

    await logPresentationEvent({ log: reloaded, signer: SIGNER, clientId: 'https://c.example' });
    const after = await reloaded.list();
    expect(after).toHaveLength(3);
    expect(pick(after.slice(0, 2))).toEqual(pick(before));

    // 採番方式は公開契約にしない。既存と衝突せず、保存先のキー順で末尾に来ることだけを見る。
    const third = after[2];
    expect(before.map((entry) => entry.id)).not.toContain(third?.id);
    const keys = (await storage.list(DASHBOARD_LOG_KEY_PREFIX)).sort();
    expect(keys).toHaveLength(3);
    expect(keys.at(-1)).toBe(`${DASHBOARD_LOG_KEY_PREFIX}${third?.id}`);

    // 再読込後の追記も既存の署名チェーンに連なる。
    expect(third?.prevHash).not.toBeNull();
    const verification = await reloaded.verify({
      alg: SIGNER.alg,
      publicKeyJwk: SIGNER.publicKeyJwk,
    });
    expect(verification.ok).toBe(true);
    expect(verification.issues).toEqual([]);
    expect(verification.count).toBe(3);
  });

  test('公開定数だけで組んだキーを消すと全件が消える（組込先の全件削除と同じ操作）', async () => {
    const { storage, log } = await logWithTwoPresentations();
    const entries = await log.list();
    // 組込先（Extension）の保持期間による全件削除と同じキーの組み立て。
    const deleteKeys = entries.map((entry) => `${DASHBOARD_LOG_KEY_PREFIX}${entry.id}`);
    deleteKeys.push(DASHBOARD_LOG_TAIL_ANCHOR_KEY);
    for (const key of deleteKeys) await storage.delete(key);

    expect(await log.list()).toEqual([]);
    expect(storage.keys()).toEqual([]);
  });
});
