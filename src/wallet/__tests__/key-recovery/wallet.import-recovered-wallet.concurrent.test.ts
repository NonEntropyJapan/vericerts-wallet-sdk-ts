/**
 * `importRecoveredWallet` の並行呼び出し。1043 ガードの検査と seed 差し替えは同一臨界区間で
 * 行われ、2 つ目の復旧は Passkey 作成・PIN 設定へ進む前に 1043 で拒否される。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import type { KdfParams } from '../../../internal/keymanager/kdf.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

setDefaultTimeout(KDF_TIMEOUT_MS);

const MNEMONIC_A =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const MNEMONIC_B = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };

describe('Wallet.importRecoveredWallet の並行呼び出し', () => {
  it('空の端末への並行復旧は 2 つ目が 1043 で拒否され、その Passkey / PIN には触れない', async () => {
    const storage = new MemoryStorage();
    const wallet = await createWallet({ storage, kdf: MIN_ARGON2ID });
    const passkeys: string[] = [];
    const pins: string[] = [];
    const call = (label: string, mnemonic: string, password: string) =>
      wallet.importRecoveredWallet(mnemonic, {
        walletPassword: password,
        newPin: '123456',
        createPasskey: async () => {
          passkeys.push(label);
        },
        setPin: async () => {
          pins.push(label);
        },
      });

    const results = await Promise.allSettled([
      call('A', MNEMONIC_A, 'password A correct'),
      call('B', MNEMONIC_B, 'password B correct'),
    ]);

    expect(results[0]?.status).toBe('fulfilled');
    expect(results[1]).toMatchObject({ status: 'rejected', reason: { code: '1043' } });
    expect(passkeys).toEqual(['A']);
    expect(pins).toEqual(['A']);
    // vault は 1 つ目（A）のまま。
    await wallet.unlockMnemonic('password A correct');
    expect(await wallet.exportMnemonic()).toBe(MNEMONIC_A);
  });
});
