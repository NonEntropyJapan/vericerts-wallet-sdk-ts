/**
 * wallet ファサードの exportMnemonic 配線検証。
 *
 * KeyManager の永続化・アンロック基盤がファサード経由で正しく公開されることを確認する:
 * - importMnemonic（persistPassword）→ unlock 済みで exportMnemonic が元ニーモニックを返す
 * - 未アンロックで export は 1005 / 未永続で export は 1042
 * - unlockMnemonic での復元・lockMnemonic / isMnemonicUnlocked
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import type { ErrorCode } from '../../internal/errors.js';
import { VericertsError } from '../../internal/errors.js';
import { KDF_TIMEOUT_MS } from '../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import { MemoryStorage } from '../../storage/storage.js';
import { createWallet } from '../factory.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'correct horse battery staple';

async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error('expected rejection');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
  }
}

describe('Wallet.exportMnemonic', () => {
  it('persistPassword 付き import 後、アンロック済みで元ニーモニックを返す', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    expect(wallet.isMnemonicUnlocked()).toBe(true);
    expect(await wallet.exportMnemonic()).toBe(TEST_MNEMONIC);
  });

  it('lockMnemonic 後の export は 1005（未アンロック）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    wallet.lockMnemonic();
    expect(wallet.isMnemonicUnlocked()).toBe(false);
    await expectRejectCode(wallet.exportMnemonic(), '1005');
  });

  it('未永続（persistPassword なし import）での export は 1042', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    await expectRejectCode(wallet.exportMnemonic(), '1042');
  });

  it('storage を共有する別 Wallet を unlockMnemonic して export できる', async () => {
    const storage = new MemoryStorage();
    const first = await createWallet({ storage });
    await first.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });

    const reopened = await createWallet({ storage });
    expect(reopened.isMnemonicUnlocked()).toBe(false);
    await expectRejectCode(reopened.exportMnemonic(), '1005');
    await reopened.unlockMnemonic(PASSWORD);
    expect(await reopened.exportMnemonic()).toBe(TEST_MNEMONIC);
  });

  it('誤パスワードでの unlockMnemonic は 1050', async () => {
    const storage = new MemoryStorage();
    const first = await createWallet({ storage });
    await first.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    const reopened = await createWallet({ storage });
    await expectRejectCode(reopened.unlockMnemonic('wrong password'), '1050');
    expect(reopened.isMnemonicUnlocked()).toBe(false);
  });
});
