/**
 * `importMnemonic({ persistPassword })` / `encrypt` のパスワード入力検査。
 *
 * 空文字は KDF 入力として成立して実質無鍵の vault ができ、非文字列は KDF 側の暗黙変換に任せると
 * 挙動が不定になる。`importRecoveredWallet` の `walletPassword`（1031）と同じ規律を揃える。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import type { ErrorCode } from '../../errors.js';
import { VericertsError } from '../../errors.js';
import type { KdfParams } from '../kdf.js';
import { KeyManager } from '../keymanager.js';
import { MNEMONIC_VAULT_KEY } from '../vault/mnemonic-vault.js';
import { KDF_TIMEOUT_MS } from './kdf-policy/kdf-timeout.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const MNEMONIC_A =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const MNEMONIC_B = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };

async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(code);
}

describe('importMnemonic の persistPassword 検査', () => {
  it.each([
    ['空文字', ''],
    ['数値', 5],
    ['null', null],
    ['オブジェクト', {}],
  ])('persistPassword が%sなら 1031 で拒否し、既存の seed・vault を変えない', async (_name, bad) => {
    const storage = new MemoryStorage();
    const km = new KeyManager({ kdf: MIN_ARGON2ID, storage });
    await km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: 'good password' });
    const before = await storage.get(MNEMONIC_VAULT_KEY);
    const keyBefore = (await km.deriveKey("m/44'/60'/0'/0/0")).address;

    await expectRejectCode(
      km.importMnemonic(MNEMONIC_B, undefined, undefined, {
        persistPassword: bad as unknown as string,
      }),
      '1031',
    );

    expect(await storage.get(MNEMONIC_VAULT_KEY)).toEqual(before);
    expect(km.isMnemonicUnlocked()).toBe(true);
    expect((await km.deriveKey("m/44'/60'/0'/0/0")).address).toBe(keyBefore);
  });

  it('persistPassword 未指定（undefined）は従来どおり永続化なしで受理する', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID, storage: new MemoryStorage() });
    await km.importMnemonic(MNEMONIC_A, undefined, undefined, { persistPassword: undefined });
    expect(km.isMnemonicUnlocked()).toBe(false);
  });
});

describe('encrypt のパスワード検査', () => {
  it.each([
    ['空文字', ''],
    ['数値', 5],
    ['undefined', undefined],
  ])('password が%sなら 1051 で拒否する', async (_name, bad) => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    await expectRejectCode(km.encrypt(new Uint8Array([1, 2, 3]), bad as unknown as string), '1051');
  });

  it('1 文字以上の文字列は受理して往復できる', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    const envelope = await km.encrypt(new Uint8Array([1, 2, 3]), 'x');
    expect(Array.from(await km.decrypt(envelope, 'x'))).toEqual([1, 2, 3]);
  });
});
