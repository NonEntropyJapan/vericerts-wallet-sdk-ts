/**
 * seed を切り替える経路（importMnemonic / recoverFromShamirShares / unlock / zeroize）は単一のキーロックで
 * 直列化する。overwrite ガード（1043）の検査と永続化は同一臨界区間で、メモリ seed と永続 vault は常に一致する。
 *
 * 実時間ではなく、ストレージ書込の保留（ゲート）と開始履歴カウンタで順序を決定的に pin する。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { mnemonicToSeed } from '../../hd.js';
import { KeyManager } from '../../keymanager.js';
import { MNEMONIC_VAULT_KEY } from '../../vault/mnemonic-vault.js';
import { KDF_TIMEOUT_MS } from '../kdf-policy/kdf-timeout.js';
import {
  allZero,
  deferred,
  ETH_PATH,
  MIN_ARGON2ID,
  MNEMONIC_A,
  MNEMONIC_B,
  newKeyManager,
  PW_A,
  PW_B,
  settle,
} from './harness.js';

setDefaultTimeout(KDF_TIMEOUT_MS);

/** A / B の SLIP-0039 シェア（2-of-3）を別 KeyManager で作る。 */
async function sharesOf(mnemonic: string): Promise<string[]> {
  const km = new KeyManager({ kdf: MIN_ARGON2ID, storage: new MemoryStorage() });
  await km.importMnemonic(mnemonic, undefined, undefined, { persistPassword: 'pw-share-source' });
  return (await km.createShamirShares(2, 3)).shares.slice(0, 2);
}

/** 有効 seed（deriveKey の導出元）が、永続 vault のニーモニックと一致するか。 */
async function activeSeedMatchesVault(km: KeyManager, password: string): Promise<string> {
  const derived = await km.deriveKey(ETH_PATH);
  km.lockMnemonic();
  await km.unlock(password);
  const persisted = await km.exportMnemonic();
  const expected = new KeyManager();
  await expected.importMnemonic(persisted);
  const expectedKey = await expected.deriveKey(ETH_PATH);
  expect(derived.address).toBe(expectedKey.address);
  return persisted;
}

describe('並行 importMnemonic の直列化', () => {
  it('1 つ目の永続化が保留中の間、2 つ目はストレージへ一切触れず、解放後に順番どおり実行される', async () => {
    const { km, storage } = newKeyManager();
    const gate = deferred();
    storage.gate = gate.promise;

    const first = km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A });
    const second = km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B });
    // 1 つ目の書込が保留に入るまで（KDF を含む）待つ。
    while (storage.started.length === 0) {
      await settle();
    }
    await settle();
    const startedWhileHeld = storage.started.length;
    // 2 つ目の書込は 1 つ目の完了まで開始されない（排他）。
    storage.gate = null;
    gate.resolve();
    await Promise.all([first, second]);

    // 2 つ目は 1 つ目の全書込（envelope+flag）の後に始まる。
    expect(startedWhileHeld).toBeLessThanOrEqual(1);
    const firstKeys = storage.started.slice(0, 2);
    expect(firstKeys.every((k) => k.startsWith('set:'))).toBe(true);
    // 最終状態: 後に開始した B が有効で、メモリ seed と vault が一致する。
    expect(await activeSeedMatchesVault(km, PW_B)).toBe(MNEMONIC_B);
  });

  // 直列化はロックの順序で決まり決定的（各回の KDF コストが重いので 5 回で足りる。20 回は負荷時に 120 s を超えた）。
  it('別ニーモニックの並行 import を 5 回繰り返しても、メモリ seed と永続 vault は常に一致する', async () => {
    for (let i = 0; i < 5; i += 1) {
      const { km } = newKeyManager();
      const results = await Promise.allSettled([
        km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A }),
        km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B }),
      ]);
      expect(results.map((r) => r.status)).toEqual(['fulfilled', 'fulfilled']);
      // 直列化されるので常に後発（B）が勝つ（実行順が入替わらない）。
      expect(await activeSeedMatchesVault(km, PW_B)).toBe(MNEMONIC_B);
    }
  });

  it('1 つ目が失敗しても 2 つ目は実行される（ロックが詰まらない）', async () => {
    const { km, storage } = newKeyManager();
    storage.failWhen = (_op, _key, nth) => nth === 1;
    const [first, second] = await Promise.allSettled([
      km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A }),
      km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B }),
    ]);
    expect(first.status).toBe('rejected');
    expect(second.status).toBe('fulfilled');
    expect(await activeSeedMatchesVault(km, PW_B)).toBe(MNEMONIC_B);
  });
});

describe('並行 recoverFromShamirShares の overwrite ガード', () => {
  it('vault が空でも別ニーモニックの並行復旧は 2 つ目が 1043 で拒否され、1 つ目の seed が残る', async () => {
    const [sa, sb] = [await sharesOf(MNEMONIC_A), await sharesOf(MNEMONIC_B)];
    const { km, storage } = newKeyManager();
    const results = await Promise.allSettled([
      km.recoverFromShamirShares(sa, { persistPassword: PW_A }),
      km.recoverFromShamirShares(sb, { persistPassword: PW_B }),
    ]);
    expect(results[0]?.status).toBe('fulfilled');
    expect(results[1]).toMatchObject({ status: 'rejected', reason: { code: '1043' } });
    // 拒否された 2 つ目はストレージへ書いていない。
    expect(
      storage.started.filter((k) => k.startsWith('set:') && k.endsWith(MNEMONIC_VAULT_KEY)),
    ).toHaveLength(1);
    expect(await activeSeedMatchesVault(km, PW_A)).toBe(MNEMONIC_A);
  });

  it('overwriteExisting: true の並行復旧は直列化され、最終状態は後発で一貫する', async () => {
    const [sa, sb] = [await sharesOf(MNEMONIC_A), await sharesOf(MNEMONIC_B)];
    const { km } = newKeyManager();
    await Promise.all([
      km.recoverFromShamirShares(sa, { persistPassword: PW_A, overwriteExisting: true }),
      km.recoverFromShamirShares(sb, { persistPassword: PW_B, overwriteExisting: true }),
    ]);
    expect(await activeSeedMatchesVault(km, PW_B)).toBe(MNEMONIC_B);
  });

  it('復旧と import の並行でも 1043 ガードが効く（2 つ目の復旧が拒否）', async () => {
    const sb = await sharesOf(MNEMONIC_B);
    const { km } = newKeyManager();
    const results = await Promise.allSettled([
      km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A }),
      km.recoverFromShamirShares(sb, { persistPassword: PW_B }),
    ]);
    expect(results[0]?.status).toBe('fulfilled');
    expect(results[1]).toMatchObject({ status: 'rejected', reason: { code: '1043' } });
    expect(await activeSeedMatchesVault(km, PW_A)).toBe(MNEMONIC_A);
  });
});

describe('zeroize / unlock と import の競合', () => {
  it('import 中の zeroize は seed の復活を許さない（1005 で拒否し、メモリは空のまま）', async () => {
    const { km, storage } = newKeyManager();
    const gate = deferred();
    storage.gate = gate.promise;
    const pending = km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A });
    pending.catch(() => undefined);
    while (storage.started.length === 0) {
      await settle();
    }
    km.zeroize();
    gate.resolve();
    await expect(pending).rejects.toMatchObject({ code: '1005' });
    await expect(km.deriveKey(ETH_PATH)).rejects.toMatchObject({ code: '1041' });
    expect(km.isMnemonicUnlocked()).toBe(false);
  });

  it('import 中の unlock は import 完了後に実行され、旧ニーモニックでアンロック状態を上書きしない', async () => {
    const { km, storage } = newKeyManager();
    await km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A });
    km.lockMnemonic();
    const gate = deferred();
    storage.gate = gate.promise;
    storage.resetCounters();
    const importing = km.importMnemonic(MNEMONIC_B, undefined, undefined, {
      persistPassword: PW_B,
    });
    const unlocking = km.unlock(PW_A).then(
      () => 'ok',
      (e: { code?: string }) => e.code,
    );
    while (storage.started.length === 0) {
      await settle();
    }
    storage.gate = null;
    gate.resolve();
    await importing;
    // 旧パスワードは新 envelope を開けない（1050）。アンロック状態は B のまま。
    expect(await unlocking).toBe('1050');
    expect(km.isMnemonicUnlocked()).toBe(true);
    expect(await km.exportMnemonic()).toBe(MNEMONIC_B);
    expect(allZero(mnemonicToSeed(MNEMONIC_B))).toBe(false);
  });
});
