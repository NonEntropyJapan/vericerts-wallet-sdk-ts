/**
 * `importMnemonic(…, { persistPassword })` の永続化待ちの間に `lockMnemonic()` されたら、アンロック状態を復活させない
 * 回帰テスト。
 *
 * 欠陥時の挙動: `replaceSeed` は永続化の書込を await した後、`zeroize()` の回数だけを見て施錠を検知していた。
 * `lockMnemonic()` はロックを取らない同期処理なので、書込中に施錠しても書込完了時に `markUnlocked` でアンロック状態が
 * 戻り、`exportMnemonic()` が平文ニーモニックを返す（自動ロック・Service Worker の施錠フックの後で平文が復活する fail-open）。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { KDF_TIMEOUT_MS } from '../../../src/internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import {
  deferred,
  ETH_PATH,
  MNEMONIC_A,
  MNEMONIC_B,
  newKeyManager,
  PW_A,
  settle,
} from '../../../src/internal/keymanager/__tests__/seed-replacement/harness.js';

setDefaultTimeout(KDF_TIMEOUT_MS);

describe('import の永続化待ち中の lockMnemonic はアンロック状態を復活させない', () => {
  it('regression: 永続化待ち中の lockMnemonic 後は seed を切り替えつつ施錠のまま', async () => {
    const { km: reference } = newKeyManager();
    await reference.importMnemonic(MNEMONIC_A);
    const expectedAddress = (await reference.deriveKey(ETH_PATH)).address;

    const { km, storage } = newKeyManager();
    await km.importMnemonic(MNEMONIC_B);
    const gate = deferred();
    storage.gate = gate.promise;
    storage.resetCounters();
    const pending = km.importMnemonic(MNEMONIC_A, undefined, undefined, {
      persistPassword: PW_A,
    });
    while (storage.started.length === 0) {
      await settle();
    }
    km.lockMnemonic();
    storage.gate = null;
    gate.resolve();
    await pending;

    // 施錠は維持し、平文ニーモニックを露出しない。
    expect(km.isMnemonicUnlocked()).toBe(false);
    await expect(km.exportMnemonic()).rejects.toMatchObject({ code: '1005' });
    // seed の切替と永続化は完了している（lockMnemonic は seed を消さない）。
    expect((await km.deriveKey(ETH_PATH)).address).toBe(expectedAddress);
    await km.unlock(PW_A);
    expect(await km.exportMnemonic()).toBe(MNEMONIC_A);
  });

  /** 1 つ目の import（MNEMONIC_B・永続化あり）を書込中で止め、2 つ目（MNEMONIC_A）を seedLock の順番待ちにする。 */
  async function queuedBehindWrite() {
    const { km, storage } = newKeyManager();
    const gate = deferred();
    storage.gate = gate.promise;
    const first = km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_A });
    while (storage.started.length === 0) {
      await settle();
    }
    const queued = km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A });
    first.catch(() => undefined);
    queued.catch(() => undefined);
    const release = () => {
      storage.gate = null;
      gate.resolve();
    };
    return { km, first, queued, release };
  }

  it('regression: seedLock の順番待ち中の lockMnemonic も取り消されず、施錠のまま', async () => {
    const { km, first, queued, release } = await queuedBehindWrite();
    km.lockMnemonic();
    release();
    await first;
    await queued;

    expect(km.isMnemonicUnlocked()).toBe(false);
    await expect(km.exportMnemonic()).rejects.toMatchObject({ code: '1005' });
  });

  it('regression: seedLock の順番待ち中の zeroize も取り消されず、1005 で施錠のまま seed を復活させない', async () => {
    const { km, first, queued, release } = await queuedBehindWrite();
    km.zeroize();
    release();
    await expect(first).rejects.toMatchObject({ code: '1005' });
    await expect(queued).rejects.toMatchObject({ code: '1005' });

    expect(km.isMnemonicUnlocked()).toBe(false);
    await expect(km.deriveKey(ETH_PATH)).rejects.toMatchObject({ code: '1041' });
  });
});
