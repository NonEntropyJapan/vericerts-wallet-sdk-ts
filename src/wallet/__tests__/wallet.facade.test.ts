/**
 * wallet ファサードの単位テスト。
 *
 * 鍵管理委譲（generateMnemonic / deriveKey / sign / encrypt / decrypt）と DID 系メソッドの
 * エラーハンドリング・基本振る舞いを、MemoryStorage を用いて検証する。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { VericertsError } from '../../internal/errors.js';
import { KDF_TIMEOUT_MS } from '../../internal/keymanager/__tests__/kdf-policy/kdf-timeout.js';
import { ethereumPath } from '../../internal/keymanager/hd.js';
import { recoverSecp256k1PublicKey } from '../../internal/keymanager/signer.js';
import { MemoryStorage } from '../../storage/storage.js';
import { createWallet } from '../factory.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

// BIP-39 公式オールゼロ・エントロピーのニーモニック（passphrase なし）。
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** MemoryStorage 付きの Wallet を生成する。 */
async function setup() {
  return createWallet({ storage: new MemoryStorage() });
}

/** import + 既定パス derive 済みの Wallet と KeyPair を用意する。 */
async function setupWithKey() {
  const wallet = await setup();
  await wallet.importMnemonic(TEST_MNEMONIC);
  const keyPair = await wallet.deriveKey(ethereumPath(0, 0));
  return { wallet, keyPair };
}

describe('createWallet', () => {
  it('MemoryStorage のみで Wallet を生成できる', async () => {
    const wallet = await setup();
    expect(typeof wallet.generateMnemonic).toBe('function');
    expect(typeof wallet.createDID).toBe('function');
  });
});

describe('Wallet.generateMnemonic', () => {
  it('12 語を生成する', async () => {
    const wallet = await setup();
    expect(wallet.generateMnemonic(12).split(' ').length).toBe(12);
  });

  it('24 語を生成する', async () => {
    const wallet = await setup();
    expect(wallet.generateMnemonic(24).split(' ').length).toBe(24);
  });
});

describe('Wallet.deriveKey', () => {
  it('masterSeed 未設定で呼ぶと 1041 を投げる', async () => {
    const wallet = await setup();
    try {
      await wallet.deriveKey(ethereumPath(0, 0));
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1041');
    }
  });

  it('返却値に privateKey を含めず、公開用フィールドのみを返す', async () => {
    const { keyPair } = await setupWithKey();
    expect(Object.keys(keyPair).sort()).toEqual(
      ['address', 'algorithm', 'derivationPath', 'id', 'publicKey'].sort(),
    );
    expect('privateKey' in keyPair).toBe(false);
  });
});

describe('Wallet.sign', () => {
  it('未知の keyID で呼ぶと 1004 を投げる', async () => {
    const wallet = await setup();
    try {
      await wallet.sign('deadbeef', new TextEncoder().encode('x'));
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1004');
    }
  });

  it('65 バイトの署名を返し、復元公開鍵が deriveKey の publicKey と一致する', async () => {
    const { wallet, keyPair } = await setupWithKey();
    const data = new TextEncoder().encode('hello vericerts');
    const signature = await wallet.sign(keyPair.id, data);
    expect(signature.length).toBe(65);
    // 既存 Signer は内部で keccak256(data) を施す前提。
    const digest = keccak_256(data);
    const recovered = recoverSecp256k1PublicKey(digest, signature, true);
    expect(Array.from(recovered)).toEqual(Array.from(keyPair.publicKey));
  });
});

describe('Wallet.encrypt / decrypt', () => {
  it('round-trip で平文が一致する', async () => {
    const wallet = await setup();
    const plaintext = new TextEncoder().encode('secret payload');
    const envelope = await wallet.encrypt(plaintext, 'pw-correct');
    const decrypted = await wallet.decrypt(envelope, 'pw-correct');
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it('誤パスワードで 1050 を投げる', async () => {
    const wallet = await setup();
    const envelope = await wallet.encrypt(new TextEncoder().encode('secret'), 'pw-correct');
    try {
      await wallet.decrypt(envelope, 'pw-wrong');
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1050');
    }
  });
});

describe('Wallet.createDID', () => {
  it("'key' 以外のメソッドで 2002 を投げる", async () => {
    const { wallet } = await setupWithKey();
    try {
      await wallet.createDID('ethr');
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('2002');
    }
  });

  it('未登録 keyID 指定で 1004 を投げる', async () => {
    const { wallet } = await setupWithKey();
    try {
      await wallet.createDID('key', { keyID: 'deadbeef' });
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1004');
    }
  });
});

describe('Wallet.resolveDID', () => {
  it('不正な DID 形式で 2001 を投げる', async () => {
    const wallet = await setup();
    try {
      await wallet.resolveDID('not-a-did');
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('2001');
    }
  });

  it('未登録メソッドの DID で 2002 を投げる', async () => {
    const wallet = await setup();
    try {
      await wallet.resolveDID('did:foo:abc');
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('2002');
    }
  });
});

describe('Wallet.getDID', () => {
  it('未保存の DID は null を返す', async () => {
    const wallet = await setup();
    expect(await wallet.getDID('did:key:zUnknown')).toBeNull();
  });

  it('保存データが破損して parse に失敗した場合は 2001 を投げる', async () => {
    // storage を共有し、`did/<did>` キーに JSON として不正なバイト列を直接書き込む。
    const storage = new MemoryStorage();
    const wallet = await createWallet({ storage });
    const did = 'did:key:zBroken';
    await storage.set(`did/${did}`, new TextEncoder().encode('{ not-valid-json'));
    try {
      await wallet.getDID(did);
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('2001');
    }
  });
});

describe('Wallet.zeroize', () => {
  it('zeroize 後の deriveKey は 1041 を投げる（マスターシードが消えている）', async () => {
    const wallet = await setup();
    await wallet.importMnemonic(TEST_MNEMONIC);
    wallet.zeroize();
    try {
      await wallet.deriveKey(ethereumPath(0, 0));
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe('1041');
    }
  });

  it('zeroize 後も getDID は同一 DID Document を返す（storage 上の公開情報は消さない）', async () => {
    const { wallet, keyPair } = await setupWithKey();
    const document = await wallet.createDID('key', { keyID: keyPair.id });
    wallet.zeroize();
    const stored = await wallet.getDID(document.id);
    expect(stored).toEqual(document);
  });
});
