/**
 * KeyManager.zeroize の振る舞い検証。
 *
 * 導出済み秘密鍵が消去されること、zeroize 後は再導出・署名が前提エラーになることを確認する。
 * 併せて不正系の例外メッセージに秘密が漏れないことを検証する。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { VericertsError } from '../../errors.js';
import { KeyManager } from '../keymanager.js';
import { KDF_TIMEOUT_MS } from './kdf-policy/kdf-timeout.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSPHRASE = 'super secret passphrase';
const ETH_PATH = "m/44'/60'/0'/0/0";

describe('KeyManager.zeroize', () => {
  it('zeroize 後に保持していた秘密鍵参照が全ゼロになる', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const privateKeyRef = keyPair.privateKey;
    expect(privateKeyRef.some((b) => b !== 0)).toBe(true);
    km.zeroize();
    expect(Array.from(privateKeyRef).every((b) => b === 0)).toBe(true);
  });

  it('zeroize 後は deriveKey が 1041 を投げる', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    await km.deriveKey(ETH_PATH);
    km.zeroize();
    await expect(km.deriveKey(ETH_PATH)).rejects.toMatchObject({ code: '1041' });
  });

  it('zeroize 後は getSigner が 1004 を投げる', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    km.zeroize();
    expect(() => km.getSigner(keyPair.id)).toThrow(VericertsError);
    try {
      km.getSigner(keyPair.id);
    } catch (error) {
      expect((error as VericertsError).code).toBe('1004');
    }
  });

  it('zeroize 後に保持していた signer の sign は同期 throw ではなく rejected Promise になる', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    // zeroize 前に取得した signer 参照を保持し続けるケース。
    const signer = km.getSigner(keyPair.id);
    km.zeroize();
    // privateKey が全ゼロ化され不正鍵となるため signSecp256k1Recoverable は失敗するが、
    // sign が async であれば同期 throw ではなく rejected Promise として捕捉できる。
    const data = new TextEncoder().encode('after zeroize');
    let threwSynchronously = false;
    let promise: Promise<Uint8Array>;
    try {
      promise = signer.sign(data);
    } catch {
      threwSynchronously = true;
      promise = Promise.resolve(new Uint8Array());
    }
    expect(threwSynchronously).toBe(false);
    await expect(promise).rejects.toThrow();
  });

  it('同一 path の再導出は登録済み KeyPair を返し、zeroize で最初の秘密鍵も全ゼロになる', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const first = await km.deriveKey(ETH_PATH);
    const second = await km.deriveKey(ETH_PATH);
    expect(second).toBe(first);
    expect(first.privateKey.some((b) => b !== 0)).toBe(true);
    km.zeroize();
    expect(Array.from(first.privateKey).every((b) => b === 0)).toBe(true);
  });

  it('zeroize 後に残った Signer / CredentialSigner は再導出後も 1004 で署名に失敗する', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const signer = km.getSigner(keyPair.id);
    const credentialSigner = km.getCredentialSigner(keyPair.id);
    const data = new TextEncoder().encode('after zeroize');
    await signer.sign(data);
    credentialSigner.sign(data);
    km.zeroize();
    // 同じ鍵を再導出して再登録しても、旧オブジェクトを捕捉したシグナーは復活しない。
    await km.importMnemonic(TEST_MNEMONIC);
    await km.deriveKey(ETH_PATH);
    await expect(signer.sign(data)).rejects.toMatchObject({ code: '1004' });
    expect(() => credentialSigner.sign(data)).toThrow(VericertsError);
  });

  it('不正系の VericertsError message に秘密が漏れない', async () => {
    const km = new KeyManager();
    // マスターシード未設定での deriveKey（1041）。
    let derivedError: VericertsError | undefined;
    try {
      await km.deriveKey(ETH_PATH);
    } catch (error) {
      derivedError = error as VericertsError;
    }
    expect(derivedError).toBeInstanceOf(VericertsError);
    const message = derivedError?.message ?? '';
    expect(message).not.toContain(PASSPHRASE);
    expect(message).not.toContain(TEST_MNEMONIC);

    // 誤パスワード復号（1050）。
    const envelope = await km.encrypt(new TextEncoder().encode('payload'), 'right password');
    let decryptError: VericertsError | undefined;
    try {
      await km.decrypt(envelope, 'wrong password');
    } catch (error) {
      decryptError = error as VericertsError;
    }
    const decMessage = decryptError?.message ?? '';
    expect(decMessage).not.toContain('wrong password');
    expect(decMessage).not.toContain('right password');
  });
});
