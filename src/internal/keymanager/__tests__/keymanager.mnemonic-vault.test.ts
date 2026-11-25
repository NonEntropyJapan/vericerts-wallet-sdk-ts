/**
 * KeyManager のニーモニック暗号化永続化・アンロック・exportMnemonic の振る舞い検証。
 *
 * 検証観点:
 * - persist（importMnemonic の persistPassword）→ 平文を永続化せず暗号化エンベロープのみ保存する
 * - アンロックゲート: 未アンロックでの export は 1005
 * - 非存在ゲート: 未永続での export / unlock は 1042
 * - unlock 往復・誤パスワード（1050）・lock / zeroize による施錠
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import type { ErrorCode } from '../../errors.js';
import { VericertsError } from '../../errors.js';
import { KeyManager } from '../keymanager.js';
import { MNEMONIC_VAULT_KEY } from '../vault/mnemonic-vault.js';
import { KDF_TIMEOUT_MS } from './kdf-policy/kdf-timeout.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

// BIP-39 公式オールゼロ・エントロピーのニーモニック。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'correct horse battery staple';
// 最小許可 argon2id（テスト高速化。keymanager.encrypt.test.ts と同じ狙い）。
const MIN_ARGON2ID = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 } as const;

/** VericertsError の code を assert するヘルパ。 */
async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error('expected rejection');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
  }
}

/** storage 付き KeyManager を生成する。 */
function setup(): { km: KeyManager; storage: MemoryStorage } {
  const storage = new MemoryStorage();
  const km = new KeyManager({ kdf: MIN_ARGON2ID, storage });
  return { km, storage };
}

describe('KeyManager mnemonic export (persist / unlock / export)', () => {
  it('persistPassword 指定 import で暗号化エンベロープのみ保存し平文は残さない', async () => {
    const { km, storage } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    const stored = await storage.get(MNEMONIC_VAULT_KEY);
    expect(stored).not.toBeNull();
    // V2 エンベロープ（先頭 0x02）であり、平文ニーモニックを含まない。
    expect(stored?.[0]).toBe(0x02);
    const asText = new TextDecoder().decode(stored ?? new Uint8Array());
    expect(asText.includes('abandon')).toBe(false);
  });

  it('persist 後はアンロック済みで exportMnemonic が元ニーモニックを返す', async () => {
    const { km } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    expect(km.isMnemonicUnlocked()).toBe(true);
    expect(await km.exportMnemonic()).toBe(TEST_MNEMONIC);
  });

  it('lockMnemonic 後の export は 1005（未アンロック）', async () => {
    const { km } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    km.lockMnemonic();
    expect(km.isMnemonicUnlocked()).toBe(false);
    await expectRejectCode(km.exportMnemonic(), '1005');
  });

  it('zeroize は露出用アンロックも施錠する（その後 export は 1005）', async () => {
    const { km } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    km.zeroize();
    expect(km.isMnemonicUnlocked()).toBe(false);
    await expectRejectCode(km.exportMnemonic(), '1005');
  });

  it('新規 KeyManager（施錠状態）で永続済みエンベロープを unlock して export できる', async () => {
    const { km, storage } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    // 同一 storage を共有する別インスタンス＝施錠状態から復元する。
    const reopened = new KeyManager({ kdf: MIN_ARGON2ID, storage });
    expect(reopened.isMnemonicUnlocked()).toBe(false);
    await expectRejectCode(reopened.exportMnemonic(), '1005');
    await reopened.unlock(PASSWORD);
    expect(await reopened.exportMnemonic()).toBe(TEST_MNEMONIC);
  });

  it('誤パスワードでの unlock は 1050 で施錠のまま', async () => {
    const { km, storage } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    const reopened = new KeyManager({ kdf: MIN_ARGON2ID, storage });
    await expectRejectCode(reopened.unlock('wrong password'), '1050');
    expect(reopened.isMnemonicUnlocked()).toBe(false);
  });

  it('未永続での export は 1042（ニーモニック非存在）', async () => {
    const { km } = setup();
    // import しても persistPassword なしなら永続化されない。
    await km.importMnemonic(TEST_MNEMONIC);
    await expectRejectCode(km.exportMnemonic(), '1042');
  });

  it('未永続での unlock は 1042（ニーモニック非存在）', async () => {
    const { km } = setup();
    await expectRejectCode(km.unlock(PASSWORD), '1042');
  });

  it('storage 未設定の KeyManager で persist を要求すると 1042', async () => {
    const km = new KeyManager({ kdf: MIN_ARGON2ID });
    await expectRejectCode(
      km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD }),
      '1042',
    );
  });

  it('永続化なしの再 import はアンロックを施錠する（旧ニーモニックの露出残留を防ぐ）', async () => {
    const { km } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    expect(km.isMnemonicUnlocked()).toBe(true);
    // 別のニーモニックを persist なしで再 import すると施錠され、旧エンベロープも消えるため 1042 に倒れる。
    const other = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
    await km.importMnemonic(other);
    expect(km.isMnemonicUnlocked()).toBe(false);
    await expectRejectCode(km.exportMnemonic(), '1042');
  });

  it('永続化なしの再 import は旧ウォレットのエンベロープ/フラグを消去し、旧ニーモニックを unlock / export / Shamir 分割で返さない', async () => {
    const { km, storage } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });
    const other = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
    await km.importMnemonic(other);

    expect(await storage.get(MNEMONIC_VAULT_KEY)).toBeNull();
    expect(await storage.list('keymanager/mnemonic-vault/')).toEqual([]);
    // 旧ウォレット A の PIN で unlock しても A は取り出せない（エンベロープ無し = 1042）。
    await expectRejectCode(km.unlock(PASSWORD), '1042');
    await expectRejectCode(km.exportMnemonic(), '1042');
    await expectRejectCode(km.createShamirShares(2, 3), '1042');
  });

  // 再起動後に鍵を導出する正規フローは unlock → export → import（`unlock` は seed を設定しない）。
  // ここでエンベロープを消すと、同じウォレットを読み直しただけで unlock / export / Shamir 分割の
  // 手段が失われ、次回起動時に 1042 になる。
  it('アンロック中の同一ニーモニックを永続化なしで再 import してもエンベロープを消さない', async () => {
    const { km, storage } = setup();
    await km.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });

    // 再起動相当。unlock したうえで、鍵導出のために同じニーモニックを読み直す。
    const reopened = new KeyManager({ kdf: MIN_ARGON2ID, storage });
    await reopened.unlock(PASSWORD);
    expect(await reopened.exportMnemonic()).toBe(TEST_MNEMONIC);
    await reopened.importMnemonic(TEST_MNEMONIC);
    expect(await storage.get(MNEMONIC_VAULT_KEY)).not.toBeNull();

    // さらに次の起動でも unlock できる。
    const again = new KeyManager({ kdf: MIN_ARGON2ID, storage });
    await again.unlock(PASSWORD);
    expect(await again.exportMnemonic()).toBe(TEST_MNEMONIC);
  });

  // 未アンロックでは「同じウォレットの読み直し」か「別ウォレットへの差し替え」かを判定できない。
  // 判定材料が無い以上、取り違えを防ぐ側（消す）に倒す。
  it('未アンロックでの再 import は同一ニーモニックでもエンベロープを消す', async () => {
    const { storage } = setup();
    const first = new KeyManager({ kdf: MIN_ARGON2ID, storage });
    await first.importMnemonic(TEST_MNEMONIC, undefined, undefined, { persistPassword: PASSWORD });

    const reopened = new KeyManager({ kdf: MIN_ARGON2ID, storage });
    await reopened.importMnemonic(TEST_MNEMONIC);

    expect(await storage.get(MNEMONIC_VAULT_KEY)).toBeNull();
  });
});
