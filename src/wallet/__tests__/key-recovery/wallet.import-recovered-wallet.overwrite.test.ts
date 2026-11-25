/**
 * `importRecoveredWallet` の既存ウォレット上書きガード。
 *
 * `recoverFromShamirShares`と同じく `overwriteExisting: true` を要求する。本 API は
 * Passkey 作成と PIN 検証子の設定を、取り消せない vault の上書きより**前**に実行するため、
 * ガードが無いと同一端末での誤実行で旧ウォレットの PIN 検証子まで書き換わる。
 *
 * 本体の配線検証は `wallet.import-recovered-wallet.test.ts`（行数上限のため分離）。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import { VericertsError } from '../../../internal/errors.js';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import type { KdfParams } from '../../../internal/keymanager/kdf.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const OTHER_MNEMONIC =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';
const NEW_PIN = '123456';
const WALLET_PASSWORD = 'correct horse battery staple';
// 実 argon2id(DEFAULT_KDF)は 1 テストあたり複数回の importMnemonic /
// importRecoveredWallet 呼び出しを通すと CPU 競合下でタイムアウトしフレークする。
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };

describe('Wallet.importRecoveredWallet の上書きガード', () => {
  it('既にウォレットが永続化されている端末では 1043 で拒否し、Passkey も PIN も触らない', async () => {
    // この復旧経路は「別端末からの完全復旧」だが、同一端末で誤って呼ぶと旧ウォレットのエンベロープに
    // 加えて PIN 検証子まで書き換わる（本 API は Passkey 作成・PIN 設定を vault の上書きより前に
    // 実行するため）。`recoverFromShamirShares` と同じく明示的な上書き指定を要求する。
    const storage = new MemoryStorage();
    const wallet = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await wallet.importMnemonic(TEST_MNEMONIC, undefined, undefined, {
      persistPassword: WALLET_PASSWORD,
    });

    let passkeyCreated = false;
    let pinSet = false;
    try {
      await wallet.importRecoveredWallet(OTHER_MNEMONIC, {
        walletPassword: 'another wallet password',
        newPin: NEW_PIN,
        createPasskey: async () => {
          passkeyCreated = true;
        },
        setPin: async () => {
          pinSet = true;
        },
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1043');
    }
    // 取り消せない手順どころか、取り消せる手順にも入っていないこと。
    expect(passkeyCreated).toBe(false);
    expect(pinSet).toBe(false);
    expect(await wallet.exportMnemonic()).toBe(TEST_MNEMONIC);
  });

  it('overwriteExisting: true なら既存ウォレットを置き換える', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await wallet.importMnemonic(TEST_MNEMONIC, undefined, undefined, {
      persistPassword: WALLET_PASSWORD,
    });

    await wallet.importRecoveredWallet(OTHER_MNEMONIC, {
      walletPassword: 'another wallet password',
      newPin: NEW_PIN,
      overwriteExisting: true,
      newPasskey: false,
    });

    expect(await wallet.exportMnemonic()).toBe(OTHER_MNEMONIC);
  });

  it('継承した overwriteExisting は上書きを許可しない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await wallet.importMnemonic(TEST_MNEMONIC, undefined, undefined, {
      persistPassword: WALLET_PASSWORD,
    });

    await withPollutedPrototypeAsync({ overwriteExisting: true }, async () => {
      try {
        await wallet.importRecoveredWallet(OTHER_MNEMONIC, {
          walletPassword: 'another wallet password',
          newPin: NEW_PIN,
          newPasskey: false,
        });
        throw new Error('expected rejection');
      } catch (error) {
        expect((error as VericertsError).code).toBe('1043');
      }
    });
    expect(await wallet.exportMnemonic()).toBe(TEST_MNEMONIC);
  });
});
