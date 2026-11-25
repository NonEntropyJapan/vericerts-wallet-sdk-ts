/**
 * `createShamirShares` の BIP-39 パスフレーズ検知。
 *
 * SLIP-0039 シェアにはパスフレーズ（"25 番目の語"）を埋め込めないため、パスフレーズ付きの
 * ウォレットを分割すると復旧時に別ウォレットへ着地する。これを拒否する判定が、**再起動後に
 * アンロックしただけの正規フロー**でも正しく働くことを固定する。
 *
 * 判定をセッション上の `masterSeed` との突合だけに頼ると、`masterSeed` は `importMnemonic` でしか
 * 設定されないため「再起動 → `unlockMnemonic` のみ」の状態では常に判定不能になり、パスフレーズを
 * 使っていないウォレットまで分割できなくなる（同じ状態で `exportMnemonic` は成功するので、
 * 利用者から見ると不可解な失敗になる）。
 *
 * wallet.shamir.test.ts の行数上限（linterly 300 行）を超えないよう本ファイルへ分離している。
 */

import { describe, expect, setDefaultTimeout, test } from 'bun:test';
import type { ErrorCode } from '../../../internal/errors.js';
import { VericertsError } from '../../../internal/errors.js';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import type { KdfParams } from '../../../internal/keymanager/kdf.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const MNEMONIC_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'correct horse battery staple';
// 実 argon2id(DEFAULT_KDF)は 1 テストあたり複数回の import/unlock/createShamirShares を
// 通すと CPU 競合下でタイムアウトしフレークする。keymanager/__tests__/ と同じ最小許可プロファイルへ。
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };

async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error(`expected rejection with ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
  }
}

describe('createShamirShares の BIP-39 パスフレーズ検知', () => {
  test('再起動してアンロックしただけの状態でもシェアを作成できる', async () => {
    const storage = new MemoryStorage();
    const first = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await first.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });

    // 再起動相当。masterSeed は未設定で、vault をアンロックしただけの状態。
    const reopened = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await reopened.unlockMnemonic(PASSWORD);
    expect(await reopened.exportMnemonic()).toBe(MNEMONIC_12);

    const { shares } = await reopened.createShamirShares(2, 3);
    expect(shares).toHaveLength(3);
  });

  test('パスフレーズ付きウォレットは再起動後も 1011 で拒否する', async () => {
    const storage = new MemoryStorage();
    const first = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await first.importMnemonic(MNEMONIC_12, 'my bip39 passphrase', undefined, {
      persistPassword: PASSWORD,
    });

    const reopened = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await reopened.unlockMnemonic(PASSWORD);
    await expectRejectCode(reopened.createShamirShares(2, 3), '1011');
  });

  // seed 導出は `passphrase ?? ''` なので、空文字・null はパスフレーズ無しと同一 seed になる。
  // フラグも同じ正規化で決めないと、同一ウォレットの SLIP-0039 バックアップが恒久拒否される。
  test.each([
    ['空文字', ''],
    ['null', null],
  ])('パスフレーズに %s を渡した import は分割でき、復旧後も同じアドレスに着地する', async (_label, passphrase) => {
    const storage = new MemoryStorage();
    const wallet = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await wallet.importMnemonic(MNEMONIC_12, passphrase as unknown as string, undefined, {
      persistPassword: PASSWORD,
    });
    const expected = (await wallet.deriveKey("m/44'/60'/0'/0/0")).address;

    const { shares } = await wallet.createShamirShares(2, 3);
    expect(shares).toHaveLength(3);

    const restored = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await restored.recoverFromShamirShares(shares.slice(0, 2), {
      persistPassword: PASSWORD,
    });
    expect(result.status).toBe('success');
    expect((await restored.deriveKey("m/44'/60'/0'/0/0")).address).toBe(expected);
  });

  // フラグ導入前に永続化されたウォレット（フラグが無い）は判定材料が無いため、安全側に倒して
  // 拒否する。利用者は一度 importMnemonic し直せば分割できる。
  test('パスフレーズ使用有無を判定できない場合は拒否する', async () => {
    const storage = new MemoryStorage();
    const first = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await first.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    // フラグだけを取り除き、フラグ導入前のデータを再現する。
    await storage.delete('keymanager/mnemonic-vault/uses-bip39-passphrase');

    const reopened = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await reopened.unlockMnemonic(PASSWORD);
    await expectRejectCode(reopened.createShamirShares(2, 3), '1011');
  });
});
