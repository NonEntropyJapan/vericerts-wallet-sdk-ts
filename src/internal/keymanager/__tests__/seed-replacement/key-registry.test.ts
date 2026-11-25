/**
 * seed を差し替える経路は、旧 seed 由来の keys レジストリ（秘密鍵・再導出キャッシュ）を全て
 * ゼロ化・破棄し、旧 keyId での署名を拒否する。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { KeyManager } from '../../keymanager.js';
import { KDF_TIMEOUT_MS } from '../kdf-policy/kdf-timeout.js';
import { allZero, ETH_PATH, MIN_ARGON2ID, MNEMONIC_A, MNEMONIC_B, PW_A, PW_B } from './harness.js';

setDefaultTimeout(KDF_TIMEOUT_MS);

const DIGEST = new Uint8Array(32).fill(7);

async function sharesOfB(): Promise<string[]> {
  const source = new KeyManager({ kdf: MIN_ARGON2ID, storage: new MemoryStorage() });
  await source.importMnemonic(MNEMONIC_B, undefined, undefined, {
    persistPassword: 'pw-source-ok',
  });
  return (await source.createShamirShares(2, 3)).shares.slice(0, 2);
}

/** 差し替え経路の形状（永続 import / 非永続 import / passphrase 違い / Shamir 復旧）。 */
const REPLACERS: ReadonlyArray<{
  name: string;
  replace: (km: KeyManager) => Promise<void>;
}> = [
  {
    name: '永続 import（別ニーモニック）',
    replace: (km) => km.importMnemonic(MNEMONIC_B, undefined, undefined, { persistPassword: PW_B }),
  },
  { name: '非永続 import（別ニーモニック）', replace: (km) => km.importMnemonic(MNEMONIC_B) },
  {
    name: '同一ニーモニック・別 passphrase',
    replace: (km) => km.importMnemonic(MNEMONIC_A, 'other passphrase'),
  },
  {
    name: 'recoverFromShamirShares（overwriteExisting）',
    replace: async (km) => {
      const result = await km.recoverFromShamirShares(await sharesOfB(), {
        persistPassword: PW_B,
        overwriteExisting: true,
      });
      expect(result.status).toBe('success');
    },
  },
];

describe('seed 差し替えで旧 keys レジストリを破棄する', () => {
  for (const { name, replace } of REPLACERS) {
    it(`${name}: 旧 keyId の署名は全経路で KEY_NOT_FOUND（1004）、秘密鍵はゼロ化される`, async () => {
      const km = new KeyManager({ kdf: MIN_ARGON2ID, storage: new MemoryStorage() });
      await km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: PW_A });
      const oldKey = await km.deriveKey(ETH_PATH);
      // 差し替え前に取得済みの署名器（`getSigner` / `getCredentialSigner`）も後から失効しなければならない。
      const heldSigner = km.getSigner(oldKey.id);
      const heldCredentialSigner = km.getCredentialSigner(oldKey.id);
      expect(allZero(oldKey.privateKey)).toBe(false);

      await replace(km);

      expect(allZero(oldKey.privateKey)).toBe(true);
      expect(() => km.getSigner(oldKey.id)).toThrow(expect.objectContaining({ code: '1004' }));
      expect(() => km.getCredentialSigner(oldKey.id)).toThrow(
        expect.objectContaining({ code: '1004' }),
      );
      expect(() => km.signRawDigest(oldKey.id, DIGEST)).toThrow(
        expect.objectContaining({ code: '1004' }),
      );
      await expect(heldSigner.sign(new Uint8Array([1]))).rejects.toMatchObject({ code: '1004' });
      expect(() => heldCredentialSigner.sign(new Uint8Array([1]))).toThrow(
        expect.objectContaining({ code: '1004' }),
      );

      // 再導出キャッシュも旧エントリを返さない: 同一 path は新 seed 由来の別オブジェクトになる。
      const fresh = await km.deriveKey(ETH_PATH);
      expect(fresh).not.toBe(oldKey);
      expect(fresh.id).not.toBe(oldKey.id);
      expect(allZero(fresh.privateKey)).toBe(false);
      expect(await km.getSigner(fresh.id).sign(new Uint8Array([1]))).toHaveLength(65);
    });
  }

  it('同一 seed の再 import でも旧レジストリは破棄され、再導出で新しい生存鍵になる', async () => {
    const km = new KeyManager();
    await km.importMnemonic(MNEMONIC_A);
    const oldKey = await km.deriveKey(ETH_PATH);
    await km.importMnemonic(MNEMONIC_A);
    expect(allZero(oldKey.privateKey)).toBe(true);
    expect(() => km.getSigner(oldKey.id)).toThrow(expect.objectContaining({ code: '1004' }));
    const fresh = await km.deriveKey(ETH_PATH);
    expect(fresh.id).toBe(oldKey.id);
    expect(fresh).not.toBe(oldKey);
    expect(allZero(fresh.privateKey)).toBe(false);
  });

  it('失敗した import（不正ニーモニック）では旧レジストリを破棄しない', async () => {
    const km = new KeyManager();
    await km.importMnemonic(MNEMONIC_A);
    const oldKey = await km.deriveKey(ETH_PATH);
    await expect(km.importMnemonic('not a valid mnemonic')).rejects.toMatchObject({ code: '1001' });
    expect(allZero(oldKey.privateKey)).toBe(false);
    expect(await km.getSigner(oldKey.id).sign(new Uint8Array([1]))).toHaveLength(65);
  });
});
