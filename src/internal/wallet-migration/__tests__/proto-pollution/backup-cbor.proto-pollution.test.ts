/**
 * CBOR 経由のバックアップ復元における `Object.prototype` 汚染耐性。
 *
 * CBOR の map キーは攻撃者が任意に選べるため、`JSON.parse` と同じく `__proto__` /
 * `constructor` を含むコンテナを食わせられる。`deserializeBackupFromCbor` は復号済みの値を
 * プロトタイプなしへ再構成するため、汚染はグローバルにも復元結果にも波及しない。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { Encoder } from 'cbor-x';
import { exportBackup, importBackup } from '../../backup.js';
import { deserializeBackupFromCbor } from '../../backup-serialize.js';
import type { BackupSource, WalletBackup } from '../../types.js';
import { testSigner } from '../fixtures.js';

const PASSPHRASE = 'correct-horse-battery';

const SOURCE: BackupSource = {
  walletId: 'urn:uuid:wallet-1',
  credentials: [{ id: 'vc-1', format: 'dc+sd-jwt', data: 'eyJ...vc1' }],
  personas: [],
  dids: [],
  settings: JSON.stringify({ locale: 'ja' }),
};

/** `backup-serialize.ts` と同一設定のエンコーダ（攻撃側の CBOR を組み立てる）。 */
const encoder = new Encoder({ useRecords: false, variableMapSize: true });

/**
 * オブジェクトリテラルでは `__proto__` がプロトタイプ設定に化けるため、`defineProperty` で
 * **own データプロパティ**として生やす（CBOR の map キーとして符号化される）。
 */
function withOwnKey(source: object, key: string, value: unknown): object {
  const clone = { ...source };
  Object.defineProperty(clone, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
  return clone;
}

describe('deserializeBackupFromCbor の Object.prototype 汚染耐性', () => {
  afterEach(() => {
    // 万一汚染された場合でも後続テストへ波及させない。
    delete (Object.prototype as Record<string, unknown>).polluted;
  });

  it.each([
    '__proto__',
    'constructor',
  ])('%s キーを含む CBOR で Object.prototype を汚染できない', async (key) => {
    const backup = await exportBackup(SOURCE, testSigner(), {
      passphrase: PASSPHRASE,
      iterations: 1000,
    });
    const poisoned = encoder.encode(withOwnKey(backup, key, { polluted: true }));

    const restored = deserializeBackupFromCbor(new Uint8Array(poisoned));

    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect((restored as unknown as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.getPrototypeOf(restored)).toBeNull();
  });

  it('汚染キーを載せたコンテナは完全性検証で弾かれる（4033）', async () => {
    const signer = testSigner();
    const backup = await exportBackup(SOURCE, signer, {
      passphrase: PASSPHRASE,
      iterations: 1000,
    });
    const poisoned = encoder.encode(withOwnKey(backup, 'constructor', { polluted: true }));
    const restored = deserializeBackupFromCbor(new Uint8Array(poisoned));

    const promise = importBackup(restored as WalletBackup, PASSPHRASE, signer.publicKeyJwk);
    await expect(promise).rejects.toMatchObject({ code: '4033' });
  });
});
