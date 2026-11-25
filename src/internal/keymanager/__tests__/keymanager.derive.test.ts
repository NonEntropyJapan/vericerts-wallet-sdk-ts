/**
 * KeyManager の鍵導出（importMnemonic → deriveKey）の振る舞い検証。
 *
 * BIP-39 公式テストニーモニックと標準 Ethereum 導出パスから、既知の EIP-55
 * アドレスへ一致することを確認する。KeyPair の各フィールド・決定性・未初期化エラーも検証する。
 */

import { describe, expect, it } from 'bun:test';
import { VericertsError } from '../../errors.js';
import { KeyManager } from '../keymanager.js';

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
// m/44'/60'/0'/0/0 における既知の Ethereum アドレス（EIP-55）。
const KNOWN_ADDRESS = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';
const ETH_PATH = "m/44'/60'/0'/0/0";

describe('KeyManager.deriveKey', () => {
  it('importMnemonic 後に既知の EIP-55 アドレスへ一致する', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    expect(keyPair.address).toBe(KNOWN_ADDRESS);
  });

  it('KeyPair の各フィールドが期待どおり', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    expect(keyPair.algorithm).toBe('secp256k1');
    expect(keyPair.derivationPath).toBe(ETH_PATH);
    expect(keyPair.publicKey.length).toBe(33);
    expect(keyPair.privateKey.length).toBe(32);
    expect(keyPair.id.length).toBeGreaterThan(0);
    // id は公開鍵の SHA-256 hex（64 文字）。
    expect(keyPair.id).toMatch(/^[0-9a-f]{64}$/);
  });

  it('同一パスを 2 回導出すると id が一致する（決定性）', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const first = await km.deriveKey(ETH_PATH);
    const second = await km.deriveKey(ETH_PATH);
    expect(second.id).toBe(first.id);
    expect(second.address).toBe(first.address);
  });

  it('マスターシード未設定で deriveKey を呼ぶと 1041 を投げる', async () => {
    const km = new KeyManager();
    await expect(km.deriveKey(ETH_PATH)).rejects.toMatchObject({
      code: '1041',
    });
    await expect(km.deriveKey(ETH_PATH)).rejects.toBeInstanceOf(VericertsError);
  });
});
