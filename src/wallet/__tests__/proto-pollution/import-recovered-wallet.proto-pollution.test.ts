/**
 * Wallet.importRecoveredWalletの `Object.prototype` 汚染耐性テスト。
 *
 * `recovery/facade.ts` は `newPasskey` / `wuaProviderEndpoint` / `newPin` を own 限定
 * （`ownProperty`）で読む設計だが、回帰テストが存在しなかった
 * 本ファイルは「これらを**省略した**正当な呼び出し」に対して
 * 継承値が漏れ込まないことを検証する。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import { KDF_TIMEOUT_MS } from '../../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../factory.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const NEW_PIN = '123456';
const WALLET_PASSWORD = 'correct horse battery staple';

describe('Wallet.importRecoveredWallet の Object.prototype 汚染耐性', () => {
  it('継承した newPasskey: false は Passkey 作成のスキップを引き起こさない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    let passkeyCreated = false;

    const result = await withPollutedPrototypeAsync({ newPasskey: false }, () =>
      // newPasskey を渡していない呼び出し。汚染値（false）を拾えば createPasskey が
      // 呼ばれずスキップされてしまう。
      wallet.importRecoveredWallet(TEST_MNEMONIC, {
        walletPassword: WALLET_PASSWORD,
        newPin: NEW_PIN,
        createPasskey: async () => {
          passkeyCreated = true;
        },
      }),
    );

    expect(passkeyCreated).toBe(true);
    expect(result.walletId.length).toBeGreaterThan(0);
  });

  it('継承した wuaProviderEndpoint は WUA 再発行を起動しない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });

    const result = await withPollutedPrototypeAsync(
      { wuaProviderEndpoint: 'https://attacker.example/wua' },
      () =>
        // wuaProviderEndpoint を渡していない呼び出し。汚染値を拾えば攻撃者エンドポイントへ
        // WUA 取得リクエストが飛ぶ（ペルソナ鍵での challenge 署名を含む）。
        wallet.importRecoveredWallet(TEST_MNEMONIC, {
          walletPassword: WALLET_PASSWORD,
          newPin: NEW_PIN,
          newPasskey: false,
        }),
    );

    // 汚染値を拾っていれば存在しないホストへの fetch が失敗し 1033 で reject するか、
    // 拾っていなければ WUA 再発行自体をスキップして wuaRenewed: false のまま成功する。
    expect(result.wuaRenewed).toBe(false);
  });
});
