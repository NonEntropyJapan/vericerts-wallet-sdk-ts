/**
 * `signSIWE` のユニットテスト。
 *
 * 実鍵（`KeyManager`）で生成した SIWE メッセージへ署名し、既存の検証側 `verifyEoaSignature` で
 * 同じアドレスへ検証できることを確認する（往復テスト。独自実装を独自実装だけで検証しない）。
 */

import { describe, expect, it } from 'bun:test';
import { KeyManager } from '../../../keymanager/keymanager.js';
import { generateSiweMessage, type SiweParams } from '../siwe.js';
import { signSIWE } from '../siwe-sign.js';
import { verifyEoaSignature } from '../siwe-verify.js';

const TEST_MNEMONIC = 'test test test test test test test test test test test junk';
const ETH_PATH = "m/44'/60'/0'/0/0";

async function setup() {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  const keyPair = await km.deriveKey(ETH_PATH);
  const signer = km.getSigner(keyPair.id);
  return { km, keyPair, signer };
}

describe('signSIWE', () => {
  it('ERC-191 準拠の署名文字列を返し、verifyEoaSignature で同じアドレスへ検証できる', async () => {
    const { signer, keyPair } = await setup();
    const params: SiweParams = {
      domain: 'example.com',
      address: keyPair.address,
      uri: 'https://example.com/login',
      nonce: 'abcd1234',
      chainId: 1,
      statement: 'Sign in with Ethereum',
      issuedAt: new Date('2026-07-02T00:00:00.000Z'),
    };
    const message = generateSiweMessage(params);

    const signature = await signSIWE(message, signer);

    expect(signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
    expect(verifyEoaSignature(message, signature, keyPair.address)).toBe(true);
  });

  it('別アドレスに対する検証は失敗する', async () => {
    const { signer, keyPair } = await setup();
    const params: SiweParams = {
      domain: 'example.com',
      address: keyPair.address,
      uri: 'https://example.com/login',
      nonce: 'abcd1234',
      chainId: 1,
    };
    const message = generateSiweMessage(params);

    const signature = await signSIWE(message, signer);

    expect(
      verifyEoaSignature(message, signature, '0x0000000000000000000000000000000000000001'),
    ).toBe(false);
  });
});
