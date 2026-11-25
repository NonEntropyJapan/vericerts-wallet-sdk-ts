/**
 * `KeyManager.importMnemonic` の `Object.prototype` 汚染耐性テスト。
 *
 * `options?.persistPassword` をプロトタイプ鎖で読むと、永続化を**要求していない** import でも
 * 汚染値が「永続化する」を満たし、BIP-39 ニーモニックが攻撃者の選んだパスワードで暗号化されて
 * ストレージに保存される（以後そのパスワードで復号できる ＝ 鍵の持ち出し）。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { withPollutedPrototypeAsync } from '../../../__tests__/prototype-pollution.fixtures.js';
import { KeyManager } from '../../keymanager.js';
import { MNEMONIC_VAULT_KEY } from '../../vault/mnemonic-vault.js';
import { KDF_TIMEOUT_MS } from '../kdf-policy/kdf-timeout.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

// BIP-39 公式オールゼロ・エントロピーのニーモニック。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ATTACKER_PASSWORD = 'attacker-chosen-password';
// 最小許可 argon2id（テスト高速化）。
const MIN_ARGON2ID = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 } as const;

describe('KeyManager.importMnemonic の Object.prototype 汚染耐性', () => {
  it('継承した persistPassword ではニーモニックを永続化しない', async () => {
    const storage = new MemoryStorage();
    const km = new KeyManager({ kdf: MIN_ARGON2ID, storage });

    await withPollutedPrototypeAsync({ persistPassword: ATTACKER_PASSWORD }, async () => {
      // `options` は渡すが `persistPassword` は指定しない（言語オプションだけ指定する等の
      // 正当な呼び出し）。`options?.persistPassword` はここでプロトタイプ鎖を辿る。
      await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, {});
    });

    // 汚染値を拾っていれば暗号化エンベロープが保存されている。
    expect(await storage.get(MNEMONIC_VAULT_KEY)).toBeNull();
  });

  it('継承した persistPassword では攻撃者パスワードでのアンロックが成立しない', async () => {
    const storage = new MemoryStorage();
    const km = new KeyManager({ kdf: MIN_ARGON2ID, storage });

    await withPollutedPrototypeAsync({ persistPassword: ATTACKER_PASSWORD }, async () => {
      await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, {});
    });

    // 永続化されていないので 1042（未永続）で失敗するのが正。
    await expect(km.unlock(ATTACKER_PASSWORD)).rejects.toThrow();
  });

  it('options 自身のプロトタイプ経由の persistPassword も採用しない', async () => {
    const storage = new MemoryStorage();
    const km = new KeyManager({ kdf: MIN_ARGON2ID, storage });
    const inherited = Object.create({ persistPassword: ATTACKER_PASSWORD }) as {
      persistPassword?: string;
    };
    expect(Object.hasOwn(inherited, 'persistPassword')).toBe(false);

    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, inherited);

    expect(await storage.get(MNEMONIC_VAULT_KEY)).toBeNull();
  });

  it('明示的に渡した persistPassword は従来どおり永続化する（正常系）', async () => {
    const storage = new MemoryStorage();
    const km = new KeyManager({ kdf: MIN_ARGON2ID, storage });

    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, {
      persistPassword: ATTACKER_PASSWORD,
    });

    expect(await storage.get(MNEMONIC_VAULT_KEY)).not.toBeNull();
    await km.unlock(ATTACKER_PASSWORD);
  });
});
