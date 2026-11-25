/**
 * wallet ファサードの SLIP-0039 バックアップ・復旧の配線検証。
 *
 * - createShamirShares: アンロックゲート（1005 / 1042）・threshold/total 制約（1015）
 * - recoverFromShamirShares: ラウンドトリップ（分割→復元で同一の K1 が復元される。
 *   deriveKey の結果アドレスが分割前と一致することで検証する）・シェア不足 / 不正シェアの status
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import type { ErrorCode } from '../../../internal/errors.js';
import { VericertsError } from '../../../internal/errors.js';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import { ethereumPath } from '../../../internal/keymanager/hd.js';
import type { KdfParams } from '../../../internal/keymanager/kdf.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const MNEMONIC_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const MNEMONIC_24 =
  'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title';
const PASSWORD = 'correct horse battery staple';
// createWallet 経由のテストは既定で実 argon2id(DEFAULT_KDF, m=19456,t=2)を通るため、
// 1 テストあたり複数回の import/createShamirShares/recoverFromShamirShares 呼び出しが CPU 競合下で
// Bun の既定タイムアウト(5000ms)を超えフレークする。keymanager/__tests__/ のユニットテストが
// 使う最小許可プロファイルと同じものを注入し、実測ベースで高速化する。
const MIN_ARGON2ID: KdfParams = { algo: 'argon2id', version: 1, m: 9216, t: 4, p: 1 };

async function expectRejectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error('expected rejection');
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code);
  }
}

describe('Wallet.createShamirShares', () => {
  it('未永続（persistPassword なし import）での createShamirShares は 1042', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await wallet.importMnemonic(MNEMONIC_12);
    await expectRejectCode(wallet.createShamirShares(2, 3), '1042');
  });

  it('永続済みだが lockMnemonic 後の createShamirShares は 1005（未アンロック）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await wallet.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    wallet.lockMnemonic();
    await expectRejectCode(wallet.createShamirShares(2, 3), '1005');
  });

  it.each([
    [1, 3],
    [4, 3],
    [2, 17],
    [0, 3],
  ])('threshold=%i total=%i は 1015', async (threshold, total) => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await wallet.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    await expectRejectCode(wallet.createShamirShares(threshold, total), '1015');
  });

  it('アンロック済みで shares を total 件・groupThreshold/groupCount=1 で返す', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await wallet.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const result = await wallet.createShamirShares(2, 3);
    expect(result.shares).toHaveLength(3);
    expect(new Set(result.shares).size).toBe(3);
    expect(result.groupThreshold).toBe(1);
    expect(result.groupCount).toBe(1);
    expect(result.createdAt).toBeGreaterThan(0);
  });

  it('BIP-39 パスフレーズ使用中のニーモニックでは 1011（別ウォレットへの復旧を防ぐ）', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    // passphrase 付きで import すると masterSeed はパスフレーズ込みで導出されるが、
    // シェアには常にパスフレーズ無し想定のエントロピーしか埋め込めない
    // （shamir/index.ts は EMPTY_PASSPHRASE 固定）。両者が食い違うことを検知して拒否する。
    await wallet.importMnemonic(MNEMONIC_12, 'my bip39 passphrase', undefined, {
      persistPassword: PASSWORD,
    });
    await expectRejectCode(wallet.createShamirShares(2, 3), '1011');
  });
});

describe('Wallet.recoverFromShamirShares', () => {
  it.each([
    MNEMONIC_12,
    MNEMONIC_24,
  ])('ラウンドトリップ（%s）で同一の K1 が復元される', async (mnemonic) => {
    const original = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await original.importMnemonic(mnemonic, undefined, undefined, { persistPassword: PASSWORD });
    const originalAddress = (await original.deriveKey(ethereumPath(0, 0))).address;

    const { shares } = await original.createShamirShares(3, 5);

    const recovered = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await recovered.recoverFromShamirShares(shares.slice(0, 3));
    expect(result.status).toBe('success');
    expect(result.recoveredAt).toBeGreaterThan(0);

    const recoveredAddress = (await recovered.deriveKey(ethereumPath(0, 0))).address;
    expect(recoveredAddress).toBe(originalAddress);
  });

  it('日本語ニーモニックでも同一の言語で復元され、同一の K1 が復元される', async () => {
    // entropyToMnemonic は言語省略時に既定で英語を使うため、言語を保持しないと
    // 同じエントロピーでも別の単語列＝別の BIP-39 シード（別ウォレット）に復旧してしまう。
    const original = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const japaneseMnemonic = original.generateMnemonic(12, 'ja');
    await original.importMnemonic(japaneseMnemonic, undefined, 'ja', {
      persistPassword: PASSWORD,
    });
    const originalAddress = (await original.deriveKey(ethereumPath(0, 0))).address;

    const { shares } = await original.createShamirShares(2, 3);

    const recovered = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await recovered.recoverFromShamirShares(shares.slice(0, 2));
    expect(result.status).toBe('success');

    const recoveredAddress = (await recovered.deriveKey(ethereumPath(0, 0))).address;
    expect(recoveredAddress).toBe(originalAddress);
  });

  it('任意の threshold 件の組み合わせ（末尾 3 件）でも復元できる', async () => {
    const original = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await original.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const originalAddress = (await original.deriveKey(ethereumPath(0, 0))).address;
    const { shares } = await original.createShamirShares(3, 5);

    const recovered = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await recovered.recoverFromShamirShares(shares.slice(-3));
    expect(result.status).toBe('success');
    const recoveredAddress = (await recovered.deriveKey(ethereumPath(0, 0))).address;
    expect(recoveredAddress).toBe(originalAddress);
  });

  it('threshold 未満のシェアでは insufficient_shares', async () => {
    const original = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await original.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const { shares } = await original.createShamirShares(3, 5);

    const recovered = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await recovered.recoverFromShamirShares(shares.slice(0, 2));
    expect(result.status).toBe('insufficient_shares');
    expect(result.recoveredAt).toBeUndefined();
  });

  it('空配列では insufficient_shares', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await wallet.recoverFromShamirShares([]);
    expect(result.status).toBe('insufficient_shares');
  });

  it('形式不正な単語列では invalid_share', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await wallet.recoverFromShamirShares([
      'not',
      'a',
      'valid',
      'slip39',
      'share',
      'at',
      'all',
    ]);
    expect(result.status).toBe('invalid_share');
  });

  it('チェックサム破損シェアでは invalid_share', async () => {
    const original = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await original.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const { shares } = await original.createShamirShares(2, 3);
    const [first, second] = shares;
    if (first === undefined || second === undefined) {
      throw new Error('test setup: expected at least 2 shares');
    }
    const tamperedWords = first.split(' ');
    const lastIndex = tamperedWords.length - 1;
    const lastWord = tamperedWords[lastIndex];
    tamperedWords[lastIndex] = lastWord === 'academic' ? 'acid' : 'academic';
    const tampered = tamperedWords.join(' ');

    const recovered = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await recovered.recoverFromShamirShares([tampered, second]);
    expect(result.status).toBe('invalid_share');
  });

  it('異なる分割由来のシェアを混在させると invalid_share', async () => {
    const walletA = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await walletA.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const sharesA = (await walletA.createShamirShares(2, 3)).shares;

    const walletB = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await walletB.importMnemonic(MNEMONIC_24, undefined, undefined, { persistPassword: PASSWORD });
    const sharesB = (await walletB.createShamirShares(2, 3)).shares;

    const recovered = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const firstA = sharesA[0];
    const firstB = sharesB[0];
    if (firstA === undefined || firstB === undefined) {
      throw new Error('test setup: expected at least 1 share each');
    }
    const result = await recovered.recoverFromShamirShares([firstA, firstB]);
    expect(result.status).toBe('invalid_share');
  });
});

describe('Wallet.recoverFromShamirShares の永続化と上書きガード', () => {
  // 永続化パスワードを渡さないと、復旧結果はメモリ上のマスターシードにしか残らない。
  // 次回起動（= 別インスタンス）でウォレットが消えるため、契約として固定しておく。
  it('persistPassword を渡すと復旧結果が永続化され、再起動後もアンロックできる', async () => {
    const original = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await original.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const originalAddress = (await original.deriveKey(ethereumPath(0, 0))).address;
    const { shares } = await original.createShamirShares(2, 3);

    const storage = new MemoryStorage();
    const recovered = await createWallet({ storage, kdf: MIN_ARGON2ID });
    const result = await recovered.recoverFromShamirShares(shares.slice(0, 2), {
      persistPassword: PASSWORD,
    });
    expect(result.status).toBe('success');

    // 再起動相当。永続化されていなければ unlock が 1042（ニーモニック非存在）になる。
    // `unlock` はニーモニック露出専用でマスターシードを復元しない既存設計のため、復旧内容の
    // 確認は deriveKey ではなく exportMnemonic で行う。
    const reopened = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await reopened.unlockMnemonic(PASSWORD);
    expect(await reopened.exportMnemonic()).toBe(MNEMONIC_12);
    expect(originalAddress.length).toBeGreaterThan(0);
  });

  it('persistPassword を渡さない場合は永続化されない（呼び出し側が永続化を担う契約）', async () => {
    const original = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await original.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const { shares } = await original.createShamirShares(2, 3);

    const storage = new MemoryStorage();
    const recovered = await createWallet({ storage, kdf: MIN_ARGON2ID });
    expect((await recovered.recoverFromShamirShares(shares.slice(0, 2))).status).toBe('success');

    const reopened = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await expectRejectCode(reopened.unlockMnemonic(PASSWORD), '1042');
  });

  // 旧エンベロープを残したままマスターシードだけ入れ替えると、再起動で旧ウォレットへ
  // 無警告で戻る（復旧が無かったことになる）。明示的な上書き指定を要求する。
  it('既にウォレットがある端末では 1043 で拒否し、overwriteExisting: true なら置き換える', async () => {
    const source = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await source.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const sourceAddress = (await source.deriveKey(ethereumPath(0, 0))).address;
    const { shares } = await source.createShamirShares(2, 3);

    // 別のニーモニックで既に使われている端末。
    const storage = new MemoryStorage();
    const existing = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await existing.importMnemonic(MNEMONIC_24, undefined, undefined, { persistPassword: PASSWORD });

    await expectRejectCode(existing.recoverFromShamirShares(shares.slice(0, 2)), '1043');
    // 拒否された時点で既存ウォレットは無傷。
    expect(await existing.exportMnemonic()).toBe(MNEMONIC_24);

    const result = await existing.recoverFromShamirShares(shares.slice(0, 2), {
      persistPassword: PASSWORD,
      overwriteExisting: true,
    });
    expect(result.status).toBe('success');

    const reopened = await createWallet({ storage, kdf: MIN_ARGON2ID });
    await reopened.unlockMnemonic(PASSWORD);
    // 置き換わったのは復旧元（MNEMONIC_12）のニーモニックであること。
    expect(await reopened.exportMnemonic()).toBe(MNEMONIC_12);
    expect(sourceAddress.length).toBeGreaterThan(0);
  });

  // 上書きを要求していない呼び出しで汚染値を拾うと、既存ウォレットの暗号化エンベロープが
  // 攻撃者の選んだシェア由来のニーモニックへ置き換わる。
  it('継承した overwriteExisting は上書きを許可しない', async () => {
    const source = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await source.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const { shares } = await source.createShamirShares(2, 3);

    const existing = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await existing.importMnemonic(MNEMONIC_24, undefined, undefined, { persistPassword: PASSWORD });

    await withPollutedPrototypeAsync({ overwriteExisting: true }, async () => {
      await expectRejectCode(
        existing.recoverFromShamirShares(shares.slice(0, 2), { persistPassword: PASSWORD }),
        '1043',
      );
    });
    expect(await existing.exportMnemonic()).toBe(MNEMONIC_24);
  });

  it('同じシェアを重複して渡すと invalid_share（黙って 1 枚に畳まない）', async () => {
    const source = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    await source.importMnemonic(MNEMONIC_12, undefined, undefined, { persistPassword: PASSWORD });
    const { shares } = await source.createShamirShares(3, 5);
    const [first, second] = shares as [string, string];

    // 閾値 3 枚ぶん渡しているように見えるが実体は 2 種類。後勝ちで畳むと
    // 「集めたのに復元できない」がダイジェスト不一致としてしか現れず原因が伝わらない。
    const fresh = await createWallet({ storage: new MemoryStorage(), kdf: MIN_ARGON2ID });
    const result = await fresh.recoverFromShamirShares([first, second, first]);

    expect(result.status).toBe('invalid_share');
  });
});
