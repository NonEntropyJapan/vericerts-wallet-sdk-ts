/**
 * wallet ファサードの E2E + 永続化テスト。
 *
 * importMnemonic → deriveKey → createDID → getDID / listDIDs / resolveDID の一連の流れと、
 * DID 生成の決定性を MemoryStorage を用いて検証する。
 */

import { describe, expect, it } from 'bun:test';
import { ethereumPath } from '../../internal/keymanager/hd.js';
import { MemoryStorage } from '../../storage/storage.js';
import { createWallet } from '../factory.js';

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** import + 既定パス derive 済みの Wallet と KeyPair を用意する。 */
async function setupWithKey() {
  const wallet = await createWallet({ storage: new MemoryStorage() });
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  return { wallet, keyPair };
}

describe('Wallet DID E2E', () => {
  it('keyID 指定の createDID が did:key:z... 形式・secp256k1 VM を返す', async () => {
    const { wallet, keyPair } = await setupWithKey();
    const document = await wallet.createDID('key', { keyID: keyPair.id });
    expect(document.id.startsWith('did:key:z')).toBe(true);
    const vm = document.verificationMethod[0];
    expect(vm).toBeDefined();
    expect(vm?.type).toBe('EcdsaSecp256k1VerificationKey2019');
  });

  it('keyID 省略の createDID は P-256（ES256）の did:key を SLIP-0010 既定パスで新規導出する', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const document = await wallet.createDID('key');
    expect(document.id.startsWith('did:key:zDn')).toBe(true);
    expect(document.verificationMethod[0]?.type).toBe('Multikey');
    // 既定の鍵はペルソナ index 0（SLIP-0010 `m/9256'/0'/0'/0'`）と同じなので、同じ seed からは同じ DID になる。
    const persona = await wallet.createPersona();
    expect(persona.did).toBe(document.id);
    // secp256k1 の did:key は、呼び出し側が既に保持している鍵（keyID 指定）の DID 化としてだけ作れる。
    const explicit = await setupWithKey();
    const explicitDoc = await explicit.wallet.createDID('key', { keyID: explicit.keyPair.id });
    expect(explicitDoc.id.startsWith('did:key:zQ3s')).toBe(true);
    expect(document.id).not.toBe(explicitDoc.id);
  });

  it('createDID 後 getDID が同一 Document を返す（JSON round-trip）', async () => {
    const { wallet, keyPair } = await setupWithKey();
    const created = await wallet.createDID('key', { keyID: keyPair.id });
    const fetched = await wallet.getDID(created.id);
    expect(fetched).not.toBeNull();
    expect(fetched).toEqual(created);
  });

  it('複数 DID 作成後 listDIDs が全 DID を返す', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const key0 = await wallet.deriveKey(ethereumPath(0, 0));
    const key1 = await wallet.deriveKey(ethereumPath(0, 1));
    const did0 = await wallet.createDID('key', { keyID: key0.id });
    const did1 = await wallet.createDID('key', { keyID: key1.id });
    const dids = await wallet.listDIDs();
    expect(dids.length).toBe(2);
    expect(dids).toContain(did0.id);
    expect(dids).toContain(did1.id);
  });

  it('createDID の DID を resolveDID で再解決すると verificationMethod が一致する', async () => {
    const { wallet, keyPair } = await setupWithKey();
    const created = await wallet.createDID('key', { keyID: keyPair.id });
    const resolved = await wallet.resolveDID(created.id);
    expect(resolved.verificationMethod).toEqual(created.verificationMethod);
  });

  it('同一ニーモニック・同一 keyID から同一 DID が再現する（決定性）', async () => {
    const a = await setupWithKey();
    const b = await setupWithKey();
    const didA = await a.wallet.createDID('key', { keyID: a.keyPair.id });
    const didB = await b.wallet.createDID('key', { keyID: b.keyPair.id });
    expect(didA.id).toBe(didB.id);
  });
});
