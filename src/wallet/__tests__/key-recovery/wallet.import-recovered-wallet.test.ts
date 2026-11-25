/**
 * Wallet ファサードの importRecoveredWallet 配線検証。
 *
 * createWallet 経由（実 storage / 実鍵）で以下を検証する:
 * - 既存 importMnemonic を利用してニーモニックを永続化・アンロックし、既定アカウントアドレスと
 *   walletId（WalletRecordStore の id）を返す。
 * - PIN ポリシー不適合（6 桁未満）は 1031。
 * - newPasskey が既定 true のまま createPasskey 未指定は 1032。
 * - newPasskey: false なら Passkey 作成をスキップする。
 * - wuaProviderEndpoint 未指定なら WUA 再発行をスキップし wuaRenewed: false を返す。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { VericertsError } from '../../../internal/errors.js';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import type { KdfParams } from '../../../internal/keymanager/kdf.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NEW_PIN = '123456';
// vault の暗号化鍵（K4）の導出元。アンロック用 PIN は検証子専用で鍵導出には使わない。
const WALLET_PASSWORD = 'correct horse battery staple';
// 実 argon2id(DEFAULT_KDF)は 1 テストあたり複数回の importMnemonic /
// importRecoveredWallet 呼び出しを通すと CPU 競合下でタイムアウトしフレークする。
// keymanager/__tests__/ と同じ最小許可プロファイルへ切り替える。
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };
// 既存ウォレットの上書き判定用に、`TEST_MNEMONIC` とは別のニーモニックを使う。
const _OTHER_MNEMONIC =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';

describe('Wallet.importRecoveredWallet', () => {
  it('ニーモニックを復旧し、walletId・wuaRenewed:false を返す（新規ウォレットは EOA を持たないため addresses は空）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    let passkeyCreated = false;

    const result = await wallet.importRecoveredWallet(TEST_MNEMONIC, {
      walletPassword: WALLET_PASSWORD,
      newPin: NEW_PIN,
      createPasskey: async () => {
        passkeyCreated = true;
      },
    });

    expect(passkeyCreated).toBe(true);
    expect(result.wuaRenewed).toBe(false);
    expect(result.walletId.length).toBeGreaterThan(0);
    expect(result.addresses).toEqual([]);

    // importMnemonic(persistPassword) が実際に行われ、アンロック済みになっていること。
    expect(wallet.isMnemonicUnlocked()).toBe(true);
    expect(await wallet.exportMnemonic()).toBe(TEST_MNEMONIC);
  });

  it('newPin が 6 文字未満の場合は 1031', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    try {
      await wallet.importRecoveredWallet(TEST_MNEMONIC, {
        walletPassword: WALLET_PASSWORD,
        newPin: '12345',
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1031');
    }
    // PIN ポリシー違反はニーモニックへ触れる前に拒否する。
    expect(wallet.isMnemonicUnlocked()).toBe(false);
  });

  it('newPin が文字列でない場合も 1031（.length が undefined になりポリシーチェックを素通りしない）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    try {
      // eslint 的には型エラーだが、呼び出し側が JS/any 経由で渡すケースを想定した回帰テスト。
      await wallet.importRecoveredWallet(TEST_MNEMONIC, {
        walletPassword: WALLET_PASSWORD,
        newPin: 123456 as unknown as string,
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1031');
    }
    expect(wallet.isMnemonicUnlocked()).toBe(false);
  });

  it('不正なニーモニックは 1001（Passkey 作成・PIN 設定より前に検査する）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    try {
      await wallet.importRecoveredWallet('not a valid mnemonic at all', {
        walletPassword: WALLET_PASSWORD,
        newPin: NEW_PIN,
        createPasskey: async () => {},
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1001');
    }
  });

  it('newPasskey 既定 true で createPasskey 未指定は 1032', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    try {
      await wallet.importRecoveredWallet(TEST_MNEMONIC, {
        walletPassword: WALLET_PASSWORD,
        newPin: NEW_PIN,
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1032');
    }
  });

  it('createPasskey が失敗した場合も 1032', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    try {
      await wallet.importRecoveredWallet(TEST_MNEMONIC, {
        walletPassword: WALLET_PASSWORD,
        newPin: NEW_PIN,
        createPasskey: async () => {
          throw new Error('webauthn unavailable');
        },
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1032');
    }
  });

  it('newPasskey: false なら Passkey 作成をスキップする', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await wallet.importRecoveredWallet(TEST_MNEMONIC, {
      walletPassword: WALLET_PASSWORD,
      newPin: NEW_PIN,
      newPasskey: false,
    });
    expect(result.walletId.length).toBeGreaterThan(0);
  });

  it('wuaProviderEndpoint 指定時、WUA 再発行の失敗理由を 1033 へ潰さず伝播する', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    try {
      await wallet.importRecoveredWallet(TEST_MNEMONIC, {
        walletPassword: WALLET_PASSWORD,
        newPin: NEW_PIN,
        newPasskey: false,
        wuaProviderEndpoint: 'https://provider.example/wua',
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      // Wallet Provider 未設定（10102）。ここが 2005（ペルソナ未解決）なら、WUA 発行前の
      // 既定ペルソナ確保が効いていないことを意味する（新端末復旧ではペルソナが 1 件も無い）。
      // 一律 1033 へ潰していると、呼び出し側は「何を直せばよいか」を知れない。
      expect((error as VericertsError).code).toBe('10102');
    }
  });

  // アンロック用 PIN は検証子専用であり、
  // K4（vault 暗号化鍵）の導出元として読んではならない。6 文字の PIN を KDF 入力にすると
  // 探索空間が 10^6 程度に落ち、ストレージを入手した攻撃者のオフライン総当たりの射程に入る。
  it('vault の暗号化には walletPassword を使い、newPin は KDF 入力にしない', async () => {
    const storage = new MemoryStorage();
    const wallet = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await wallet.importRecoveredWallet(TEST_MNEMONIC, {
      walletPassword: WALLET_PASSWORD,
      newPin: NEW_PIN,
      newPasskey: false,
    });

    // 別インスタンス（= 再起動相当）で、永続化された vault を walletPassword で開けること。
    const reopened = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await reopened.unlockMnemonic(WALLET_PASSWORD);
    expect(await reopened.exportMnemonic()).toBe(TEST_MNEMONIC);

    // PIN では開かない（PIN が KDF 入力に使われていない証拠）。
    const withPin = await createWallet({ storage, kdf: MIN_ARGON2ID });
    expect(withPin.unlockMnemonic(NEW_PIN)).rejects.toThrow();
  });

  it('walletPassword が無い / 文字列でない場合は 1031（ニーモニックへ触れる前に拒否）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    for (const walletPassword of [undefined, '', 123456]) {
      try {
        await wallet.importRecoveredWallet(TEST_MNEMONIC, {
          walletPassword: walletPassword as unknown as string,
          newPin: NEW_PIN,
          newPasskey: false,
        });
        throw new Error('expected rejection');
      } catch (error) {
        expect(error).toBeInstanceOf(VericertsError);
        expect((error as VericertsError).code).toBe('1031');
      }
    }
    expect(wallet.isMnemonicUnlocked()).toBe(false);
  });

  it('setPin を注入すると PIN 検証子の設定を委譲し、失敗したら復旧を中断する', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const received: string[] = [];
    await wallet.importRecoveredWallet(TEST_MNEMONIC, {
      walletPassword: WALLET_PASSWORD,
      newPin: NEW_PIN,
      newPasskey: false,
      setPin: async (pin) => {
        received.push(pin);
      },
    });
    expect(received).toEqual([NEW_PIN]);

    // 設定に失敗したら、ニーモニックを書き換える前に中断する（アンロック手段の無い
    // ウォレットを掴ませない）。
    const failing = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    try {
      await failing.importRecoveredWallet(TEST_MNEMONIC, {
        walletPassword: WALLET_PASSWORD,
        newPin: NEW_PIN,
        newPasskey: false,
        setPin: async () => {
          throw new Error('pin store unavailable');
        },
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1031');
    }
    expect(failing.isMnemonicUnlocked()).toBe(false);
  });

  // 拡張の PIN 設定 と同じ規則（コードポイント数・制御文字禁止）。
  // `pin.length`（UTF-16 コードユニット数）で数えると、SDK では通るのに extension 側の検証子設定で
  // 弾かれる PIN が作れてしまう。
  it('PIN の長さはコードポイントで数え、制御文字を拒否する', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    // サロゲートペア 5 文字（UTF-16 では 10 コードユニット）。コードポイントでは 5 で不足。
    for (const pin of ['👍👍👍👍👍', '12345']) {
      try {
        await wallet.importRecoveredWallet(TEST_MNEMONIC, {
          walletPassword: WALLET_PASSWORD,
          newPin: pin,
          newPasskey: false,
        });
        throw new Error('expected rejection');
      } catch (error) {
        expect(error).toBeInstanceOf(VericertsError);
        expect((error as VericertsError).code).toBe('1031');
      }
    }
  });

  it('制御文字を含む PIN は 1031（extension の pin-store と同じ規則）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    try {
      await wallet.importRecoveredWallet(TEST_MNEMONIC, {
        walletPassword: WALLET_PASSWORD,
        newPin: `12345${String.fromCharCode(0x7f)}`,
        newPasskey: false,
      });
      throw new Error('expected rejection');
    } catch (error) {
      expect((error as VericertsError).code).toBe('1031');
    }
    expect(wallet.isMnemonicUnlocked()).toBe(false);
  });
});
