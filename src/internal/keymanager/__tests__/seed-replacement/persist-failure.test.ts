/**
 * 永続化に失敗した seed 差し替えは、メモリ（seed・keys・アンロック）も永続化も元の状態のまま
 * にしなければならない（「永続化を先にコミットし、成功した場合にだけ seed を切り替える」）。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import type { KeyManager, KeyPair } from '../../keymanager.js';
import { recoverMnemonic } from '../../shamir/index.js';
import { MNEMONIC_VAULT_KEY } from '../../vault/mnemonic-vault.js';
import { KDF_TIMEOUT_MS } from '../kdf-policy/kdf-timeout.js';
import {
  allZero,
  type ControlledStorage,
  ETH_PATH,
  MNEMONIC_A,
  MNEMONIC_B,
  newKeyManager,
  PW_A,
  PW_B,
} from './harness.js';

setDefaultTimeout(KDF_TIMEOUT_MS);

const FLAG_KEY = 'keymanager/mnemonic-vault/uses-bip39-passphrase';

async function snapshot(
  storage: ControlledStorage,
): Promise<{ envelope: number[]; flag: number[] }> {
  return {
    envelope: Array.from((await storage.get(MNEMONIC_VAULT_KEY)) ?? []),
    flag: Array.from((await storage.get(FLAG_KEY)) ?? []),
  };
}

interface ImportedA {
  readonly km: KeyManager;
  readonly storage: ControlledStorage;
  readonly keyA: KeyPair;
  readonly before: { envelope: number[]; flag: number[] };
}

/** A を永続 import 済みで、失敗注入前の状態を返す。 */
async function importedA(): Promise<ImportedA> {
  const { km, storage } = newKeyManager();
  await km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A });
  const keyA = await km.deriveKey(ETH_PATH);
  const before = await snapshot(storage);
  storage.resetCounters();
  return { km, storage, keyA, before };
}

async function expectStateUnchanged(ctx: ImportedA): Promise<void> {
  const { km, storage, keyA, before } = ctx;
  // 永続化: エンベロープ・フラグとも元のまま。
  expect(await snapshot(storage)).toEqual(before);
  // メモリ: 旧 seed の鍵が生きており、署名できる（ゼロ化・破棄されていない）。
  expect(allZero(keyA.privateKey)).toBe(false);
  expect(await km.getSigner(keyA.id).sign(new Uint8Array([1]))).toHaveLength(65);
  expect((await km.deriveKey(ETH_PATH)).address).toBe(keyA.address);
  // アンロック状態と vault の内容は旧ニーモニックと一致する。
  expect(km.isMnemonicUnlocked()).toBe(true);
  expect(await km.exportMnemonic()).toBe(MNEMONIC_A);
  // バックアップは有効 seed（A）のものになる。
  const shares = await km.createShamirShares(2, 3);
  const recovered = recoverMnemonic(shares.shares.slice(0, 2));
  expect(recovered.status === 'success' && recovered.mnemonic).toBe(MNEMONIC_A);
}

describe('importMnemonic: 永続化失敗時は状態を変えない', () => {
  it('エンベロープ書込の失敗: seed / keys / vault とも旧状態のまま reject する', async () => {
    const ctx = await importedA();
    ctx.storage.failOnce((op, key) => op === 'set' && key === MNEMONIC_VAULT_KEY);
    await expect(
      ctx.km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B }),
    ).rejects.toThrow();
    ctx.storage.failWhen = () => false;
    await expectStateUnchanged(ctx);
  });

  it('フラグ書込の失敗（envelope+フラグの非原子書込）: 新 envelope を残さず旧状態へ戻す', async () => {
    const ctx = await importedA();
    ctx.storage.failOnce((op, key) => op === 'set' && key === FLAG_KEY);
    await expect(
      ctx.km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B }),
    ).rejects.toThrow();
    ctx.storage.failWhen = () => false;
    await expectStateUnchanged(ctx);
  });

  it('書込 N 回目で失敗しても（どの位置でも）旧状態に戻る', async () => {
    for (const failAt of [1, 2, 3, 4]) {
      const ctx = await importedA();
      // 復元書込は失敗させない: 元の書込列の failAt 番目だけ落とす。
      let failed = false;
      ctx.storage.failWhen = (_op, _key, nth) => {
        if (!failed && nth === failAt) {
          failed = true;
          return true;
        }
        return false;
      };
      const outcome = await ctx.km
        .importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B })
        .then(
          () => 'ok',
          () => 'rejected',
        );
      ctx.storage.failWhen = () => false;
      if (outcome === 'rejected') {
        await expectStateUnchanged(ctx);
      } else {
        // 書込回数が failAt に満たず失敗が起きなかった場合は import が成功し、B が有効になる。
        expect(failed).toBe(false);
        expect(await ctx.km.exportMnemonic()).toBe(MNEMONIC_B);
      }
    }
  });

  it('非永続 import の clearPersisted 失敗: 旧エンベロープを残したまま旧 seed を維持する', async () => {
    const ctx = await importedA();
    ctx.storage.failOnce((op, key) => op === 'delete' && key === FLAG_KEY);
    await expect(ctx.km.importMnemonic(MNEMONIC_B)).rejects.toThrow();
    ctx.storage.failWhen = () => false;
    await expectStateUnchanged(ctx);
  });

  it('初回 import の永続化失敗: seed は設定されず（1041）、vault も空のまま', async () => {
    const { km, storage } = newKeyManager();
    storage.failWhen = () => true;
    await expect(
      km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A }),
    ).rejects.toThrow();
    storage.failWhen = () => false;
    await expect(km.deriveKey(ETH_PATH)).rejects.toMatchObject({ code: '1041' });
    expect(km.isMnemonicUnlocked()).toBe(false);
    expect(await storage.get(MNEMONIC_VAULT_KEY)).toBeNull();
  });

  it('復元自体も失敗して vault を元に戻せないときは fail-closed（seed・keys をゼロ化して施錠）', async () => {
    const ctx = await importedA();
    // 1 回目の書込（フラグ保守化 or envelope）以降はすべて失敗 → ロールバックも失敗する。
    ctx.storage.failWhen = (_op, _key, nth) => nth >= 2;
    await expect(
      ctx.km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B }),
    ).rejects.toThrow();
    expect(allZero(ctx.keyA.privateKey)).toBe(true);
    expect(ctx.km.isMnemonicUnlocked()).toBe(false);
    await expect(ctx.km.deriveKey(ETH_PATH)).rejects.toMatchObject({ code: '1041' });
    expect(() => ctx.km.getSigner(ctx.keyA.id)).toThrow();
  });

  it('保守的フラグ: 書込が途中で途切れても passphrase 付きウォレットを SLIP-0039 に通さない', async () => {
    // passphrase 付き B を import 中に envelope 書込直後で停止（クラッシュ相当）しても、フラグは
    // 「使用あり」か正しい値のどちらかで、「使用なし」のまま新 envelope が見える窓を作らない。
    const { km, storage } = newKeyManager();
    await km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A });
    storage.resetCounters();
    storage.failOnce((op, key) => op === 'set' && key === FLAG_KEY);
    await km
      .importMnemonic(MNEMONIC_B, 'passphrase', undefined, { persistPassword: PW_B })
      .catch(() => undefined);
    storage.failWhen = () => false;
    const flag = await storage.get(FLAG_KEY);
    // ロールバック後は旧フラグ（'0'）と旧 envelope の組。新 envelope + 旧フラグの混在は残らない。
    expect(new TextDecoder().decode(flag ?? new Uint8Array())).toBe('0');
    await km.unlock(PW_A);
    expect(await km.exportMnemonic()).toBe(MNEMONIC_A);
  });

  it('同一 seed の再 import（成功）も従来どおり動作し、新 envelope で unlock できる', async () => {
    const ctx = await importedA();
    await ctx.km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B });
    expect(await ctx.km.exportMnemonic()).toBe(MNEMONIC_B);
    ctx.km.lockMnemonic();
    await ctx.km.unlock(PW_B);
    expect(await ctx.km.exportMnemonic()).toBe(MNEMONIC_B);
  });
});
