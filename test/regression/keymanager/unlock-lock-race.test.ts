/**
 * `unlock` の復号待ちの間に施錠（`zeroize` / `lockMnemonic`）されたら、アンロック状態を復活させない回帰テスト。
 *
 * 欠陥時の挙動: `KeyManager.unlock` は `vault.unlock(password)` を await し、`MnemonicVault.unlock` はエンベロープの
 * 読み出しと argon2id 復号を待った後で無条件に平文ニーモニックを保持する。`zeroize()` / `lockMnemonic()` は
 * ロックを取らない同期処理なので、復号中に施錠しても復号完了時にアンロック状態が戻り、`exportMnemonic()` が
 * 平文ニーモニックを返す（自動ロック・Service Worker の施錠フックの後で平文が復活する fail-open）。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { KDF_TIMEOUT_MS } from '../../../src/internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import {
  ControlledStorage,
  deferred,
  MNEMONIC_A,
  newKeyManager,
  PW_A,
  settle,
} from '../../../src/internal/keymanager/__tests__/seed-replacement/harness.js';
import type { KeyManager } from '../../../src/internal/keymanager/keymanager.js';

setDefaultTimeout(KDF_TIMEOUT_MS);

/** 読み出し（`get`）も保留できる storage。`unlock` のエンベロープ読み出し中に施錠する順序を決定的に作る。 */
class ReadGatedStorage extends ControlledStorage {
  readGate: Promise<void> | null = null;
  readsStarted = 0;

  override async get(key: string): Promise<Uint8Array | null> {
    this.readsStarted += 1;
    if (this.readGate !== null) {
      await this.readGate;
    }
    return super.get(key);
  }
}

/** 永続化済みで施錠された KeyManager を作る。 */
async function lockedKeyManager(): Promise<{ km: KeyManager; storage: ReadGatedStorage }> {
  const { km, storage } = newKeyManager(new ReadGatedStorage());
  await km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A });
  km.lockMnemonic();
  return { km, storage: storage as ReadGatedStorage };
}

async function expectStillLocked(km: KeyManager, pending: Promise<void>): Promise<void> {
  await expect(pending).rejects.toMatchObject({ code: '1005' });
  expect(km.isMnemonicUnlocked()).toBe(false);
  await expect(km.exportMnemonic()).rejects.toMatchObject({ code: '1005' });
}

describe('unlock 待ち中の施錠はアンロック状態を復活させない', () => {
  it('regression: unlock 待ち中の zeroize は 1005 で拒否し、施錠のまま', async () => {
    const { km } = await lockedKeyManager();
    const pending = km.unlock(PW_A);
    pending.catch(() => undefined);
    km.zeroize();
    await expectStillLocked(km, pending);
  });

  it('regression: unlock 待ち中の lockMnemonic は 1005 で拒否し、施錠のまま', async () => {
    const { km } = await lockedKeyManager();
    const pending = km.unlock(PW_A);
    pending.catch(() => undefined);
    km.lockMnemonic();
    await expectStillLocked(km, pending);
  });

  it('regression: エンベロープ読み出し中の zeroize も検知し、後続の unlock は通常どおり成功する', async () => {
    const { km, storage } = await lockedKeyManager();
    const gate = deferred();
    storage.readGate = gate.promise;
    storage.readsStarted = 0;
    const pending = km.unlock(PW_A);
    pending.catch(() => undefined);
    while (storage.readsStarted === 0) {
      await settle();
    }
    km.zeroize();
    storage.readGate = null;
    gate.resolve();
    await expectStillLocked(km, pending);

    // 施錠後に改めて呼んだ unlock は影響を受けない。
    await km.unlock(PW_A);
    expect(km.isMnemonicUnlocked()).toBe(true);
    expect(await km.exportMnemonic()).toBe(MNEMONIC_A);
  });
});
