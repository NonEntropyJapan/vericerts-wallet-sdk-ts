/**
 * DashboardLog.importLog と append の競合。importLog の空判定→連番書き込みが appendLock で
 * 直列化されず、並行 append が同じ連番を採番して互いを上書きしていた回帰を防ぐ。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { DashboardLog } from '../../dashboard-log/dashboard-log.js';
import { signingInputHash } from '../../dashboard-log/dashboard-log-shared.js';
import { fixedNow, testSigner } from './dashboard-log-helpers.js';

/** `set` を遅延させ、書き込み途中に別操作が割り込める状態を作る。 */
class SlowSetStorage extends MemoryStorage {
  override async set(key: string, value: Uint8Array): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, 5));
    await super.set(key, value);
  }
}

describe('DashboardLog 並行 importLog + append', () => {
  it('import 中の append が連番を上書きせず、chain が分岐しない', async () => {
    const signer = testSigner();
    const source = new DashboardLog(new MemoryStorage(), fixedNow('2026-07-02T00:00:00.000Z'));
    await source.append('correctionRequest', { vcId: 'vc-1', reason: 'a' }, signer);
    await source.append('correctionRequest', { vcId: 'vc-2', reason: 'b' }, signer);
    const ndjson = await source.exportLog();
    const dest = new DashboardLog(new SlowSetStorage(), fixedNow('2026-07-03T00:00:00.000Z'));

    const [imported] = await Promise.all([
      dest.importLog(ndjson, { alg: signer.alg, publicKeyJwk: signer.publicKeyJwk }),
      dest.append('presentation', { rpIdentifier: 'rp-1' }, signer),
    ]);

    expect(imported).toBe(2);
    const stored = await dest.list();
    expect(stored).toHaveLength(3);
    expect(new Set(stored.map((e) => e.id)).size).toBe(3);
    for (let i = 1; i < stored.length; i++) {
      expect(stored[i]?.prevHash).toBe(signingInputHash(stored[i - 1] as never));
    }
  });
});
