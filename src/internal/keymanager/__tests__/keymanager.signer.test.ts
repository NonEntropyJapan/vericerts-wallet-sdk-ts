/**
 * KeyManager.getSigner が返す Signer の振る舞い検証。
 *
 * sign の出力長・公開鍵復元による検証・publicKey/address の一致・未知鍵 ID のエラーを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { VericertsError } from '../../errors.js';
import { KeyManager } from '../keymanager.js';
import { recoverSecp256k1PublicKey } from '../signer.js';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ETH_PATH = "m/44'/60'/0'/0/0";

/** import + derive 済みの KeyManager と KeyPair を用意する。 */
async function setup() {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  const keyPair = await km.deriveKey(ETH_PATH);
  return { km, keyPair };
}

describe('KeyManager.getSigner', () => {
  it('sign は 65 バイトの recoverable 署名を返す', async () => {
    const { km, keyPair } = await setup();
    const signer = km.getSigner(keyPair.id);
    const data = new TextEncoder().encode('hello vericerts');
    const signature = await signer.sign(data);
    expect(signature.length).toBe(65);
  });

  it('署名から復元した公開鍵が signer.publicKey と一致する', async () => {
    const { km, keyPair } = await setup();
    const signer = km.getSigner(keyPair.id);
    const data = new TextEncoder().encode('hello vericerts');
    const signature = await signer.sign(data);
    const digest = keccak_256(data);
    const recovered = recoverSecp256k1PublicKey(digest, signature, true);
    expect(Array.from(recovered)).toEqual(Array.from(signer.publicKey()));
  });

  it('publicKey / address が KeyPair と一致する', async () => {
    const { km, keyPair } = await setup();
    const signer = km.getSigner(keyPair.id);
    expect(Array.from(signer.publicKey())).toEqual(Array.from(keyPair.publicKey));
    expect(signer.address()).toBe(keyPair.address);
  });

  it('未知の鍵 ID では 1004 を投げる', async () => {
    const { km } = await setup();
    expect(() => km.getSigner('deadbeef')).toThrow(VericertsError);
    try {
      km.getSigner('deadbeef');
    } catch (error) {
      expect((error as VericertsError).code).toBe('1004');
    }
  });
});
