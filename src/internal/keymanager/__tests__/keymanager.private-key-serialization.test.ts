/**
 * `KeyManager` が返す鍵ペアの `privateKey` がシリアライズ・列挙・複製・ログに出ないことの検証。
 *
 * 秘密鍵が JSON やログにシリアライズされないことを検証する。公開型の形は
 * 変えず、`privateKey` を列挙不可・書き換え不可・再定義不可の own データプロパティにする（`secret-key-field.ts`）。
 * `KeyPair`（secp256k1）と `P256KeyPair` の両方に同じケースを回す（実鍵・モック禁止）。
 *
 * 検証内容:
 * - 出ない: `JSON.stringify`（構造化ログ形を含む）/ `Object.keys` / `entries` / スプレッド / `for…in` / `Object.assign` /
 *   `structuredClone` / `util.inspect`（`showHidden` 含む）/ `String` / テンプレートリテラル。
 * - 読める: `.privateKey` は 32 バイトの同一 `Uint8Array`。属性は列挙・書き換え・再定義不可。中身は `fill(0)` できる。
 * - レジストリ契約: 再導出は同一オブジェクト、`zeroize()` で参照が全ゼロになり署名器が失効する。
 * - 署名経路・`Wallet.deriveKey`・プロトタイプ汚染下・型の形が従来どおり。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { inspect } from 'node:util';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createWallet } from '../../../wallet/factory.js';
import { withPollutedPrototypeAsync } from '../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../errors.js';
import { p256DidPath } from '../derivation/slip10.js';
import { KeyManager } from '../keymanager.js';
import { getSecp256k1PublicKey, recoverSecp256k1PublicKey } from '../signer.js';
import type { KeyPair, P256KeyPair, RegisteredKeyPair } from '../types.js';
import { KDF_TIMEOUT_MS } from './kdf-policy/kdf-timeout.js';

/** 実 Argon2id を通るため、並列負荷下でも既定 5000ms で落ちないよう猶予を広げる。 */
setDefaultTimeout(KDF_TIMEOUT_MS);

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ETH_PATH = "m/44'/60'/0'/0/0";

interface KeyPairCase {
  readonly name: string;
  readonly derive: (km: KeyManager) => Promise<RegisteredKeyPair>;
  /** `Object.keys` が返すべき列挙可能フィールド（`privateKey` を除く）。 */
  readonly publicFields: readonly string[];
}

const CASES: KeyPairCase[] = [
  {
    name: 'KeyPair (secp256k1)',
    derive: (km) => km.deriveKey(ETH_PATH),
    publicFields: ['id', 'algorithm', 'publicKey', 'address', 'derivationPath'],
  },
  {
    name: 'P256KeyPair (P-256)',
    derive: (km) => km.deriveP256Key(p256DidPath(0)),
    publicFields: ['id', 'algorithm', 'publicKey', 'derivationPath'],
  },
];

async function setup(derive: KeyPairCase['derive']) {
  const km = new KeyManager();
  await km.importMnemonic(TEST_MNEMONIC);
  const keyPair = await derive(km);
  return { km, keyPair };
}

/** 秘密鍵バイト列が文字列化されて現れうる形（`1,2,3` / `1, 2, 3` / `{"0":1,"1":2` / hex）。 */
function secretForms(privateKey: Uint8Array): string[] {
  const bytes = Array.from(privateKey);
  return [
    bytes.join(','),
    bytes.join(', '),
    bytes.map((b, i) => `"${i}":${b}`).join(','),
    bytes.map((b) => b.toString(16).padStart(2, '0')).join(''),
  ];
}

function expectNoSecret(text: string, privateKey: Uint8Array): void {
  expect(text).not.toContain('privateKey');
  for (const form of secretForms(privateKey)) {
    expect(text).not.toContain(form);
  }
}

describe.each(CASES)('$name の privateKey は出力・列挙・複製に出ない', ({
  derive,
  publicFields,
}) => {
  it('JSON.stringify（単体・配列・構造化ログ形）に privateKey が出ない', async () => {
    const { keyPair } = await setup(derive);
    const secret = keyPair.privateKey;
    for (const text of [
      JSON.stringify(keyPair),
      JSON.stringify({ event: 'x', keyPair }),
      JSON.stringify([keyPair]),
    ]) {
      expectNoSecret(text, secret);
    }
    expect(JSON.parse(JSON.stringify(keyPair))).not.toHaveProperty('privateKey');
  });

  it('Object.keys / entries / スプレッド / for…in / Object.assign に privateKey が出ない', async () => {
    const { keyPair } = await setup(derive);
    const forInKeys: string[] = [];
    for (const key in keyPair) {
      forInKeys.push(key);
    }
    expect(Object.keys(keyPair)).toEqual([...publicFields]);
    expect(Object.entries(keyPair).map(([key]) => key)).toEqual([...publicFields]);
    expect(Object.keys({ ...keyPair })).toEqual([...publicFields]);
    expect(Object.keys(Object.assign({}, keyPair))).toEqual([...publicFields]);
    expect(forInKeys).toEqual([...publicFields]);
    expect(Object.hasOwn({ ...keyPair }, 'privateKey')).toBe(false);
  });

  it('structuredClone の結果に privateKey が出ない', async () => {
    const { keyPair } = await setup(derive);
    const cloned = structuredClone(keyPair);
    expect(Object.hasOwn(cloned, 'privateKey')).toBe(false);
    expect(Object.keys(cloned)).toEqual([...publicFields]);
  });

  it('util.inspect（showHidden 含む）・String・テンプレートリテラルに秘密鍵が出ない', async () => {
    const { keyPair } = await setup(derive);
    const secret = keyPair.privateKey;
    const shown = inspect(keyPair, { showHidden: true, depth: 5 });
    expectNoSecret(shown, secret);
    expectNoSecret(`${inspect(keyPair)}`, secret);
    expectNoSecret(inspect({ nested: [keyPair] }, { depth: 5 }), secret);
    expectNoSecret(String(keyPair), secret);
    expectNoSecret(`${keyPair}`, secret);
    // 識別に必要な id は表示される。
    expect(shown).toContain(keyPair.id);
  });

  it('inspect.custom は列挙不可の own プロパティで、toJSON は定義しない', async () => {
    const { keyPair } = await setup(derive);
    const descriptor = Object.getOwnPropertyDescriptor(
      keyPair,
      Symbol.for('nodejs.util.inspect.custom'),
    );
    expect(descriptor?.enumerable).toBe(false);
    expect('toJSON' in keyPair).toBe(false);
  });
});

describe.each(CASES)('$name の privateKey を明示的に読む正当な利用', ({ derive, publicFields }) => {
  it('keyPair.privateKey は 32 バイトの Uint8Array で、公開フィールドは従来どおり列挙できる', async () => {
    const { keyPair } = await setup(derive);
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.privateKey.length).toBe(32);
    expect(keyPair.privateKey.some((b) => b !== 0)).toBe(true);
    expect(Object.keys(keyPair)).toEqual([...publicFields]);
  });

  it('privateKey の属性は enumerable / writable / configurable がすべて false', async () => {
    const { keyPair } = await setup(derive);
    const descriptor = Object.getOwnPropertyDescriptor(keyPair, 'privateKey');
    expect(descriptor).toMatchObject({ enumerable: false, writable: false, configurable: false });
    expect(descriptor?.value).toBe(keyPair.privateKey);
  });

  it('privateKey の差し替えと削除は TypeError で、元の値が変わらない', async () => {
    const { keyPair } = await setup(derive);
    const original = keyPair.privateKey;
    const mutable = keyPair as { privateKey?: Uint8Array };
    expect(() => {
      mutable.privateKey = new Uint8Array(32);
    }).toThrow(TypeError);
    expect(() => {
      delete mutable.privateKey;
    }).toThrow(TypeError);
    expect(keyPair.privateKey).toBe(original);
    expect(original.some((b) => b !== 0)).toBe(true);
  });

  it('privateKey 配列の中身は fill(0) できる（zeroize 用。参照の差し替えだけを防ぐ）', async () => {
    const { keyPair } = await setup(derive);
    keyPair.privateKey.fill(0);
    expect(Array.from(keyPair.privateKey).every((b) => b === 0)).toBe(true);
  });
});

describe.each(CASES)('$name のレジストリ契約', ({ derive }) => {
  it('同一パスの再導出は同一オブジェクト・同一 privateKey 配列を返す', async () => {
    const { km, keyPair } = await setup(derive);
    const again = await derive(km);
    expect(again).toBe(keyPair);
    expect(again.privateKey).toBe(keyPair.privateKey);
  });

  it('zeroize() 後は保持していた privateKey 参照が全ゼロで、署名器が 1004 で失効する', async () => {
    const { km, keyPair } = await setup(derive);
    const secret = keyPair.privateKey;
    const signer = keyPair.algorithm === 'secp256k1' ? km.getSigner(keyPair.id) : undefined;
    const credentialSigner = km.getCredentialSigner(keyPair.id);
    expect(secret.some((b) => b !== 0)).toBe(true);
    km.zeroize();
    expect(Array.from(secret).every((b) => b === 0)).toBe(true);
    if (signer !== undefined) {
      await expect(signer.sign(new Uint8Array([1]))).rejects.toMatchObject({
        code: ErrorCodes.KEY_NOT_FOUND,
      });
    }
    expect(() => credentialSigner.sign(new Uint8Array([1]))).toThrow(
      expect.objectContaining({ code: ErrorCodes.KEY_NOT_FOUND }),
    );
  });
});

describe('署名経路は従来どおり動く（secp256k1）', () => {
  it('getSigner / signRawDigest / getCredentialSigner / getSecp256k1PublicKey が動き、署名が検証できる', async () => {
    const { km, keyPair } = await setup(CASES[0]?.derive as KeyPairCase['derive']);
    const secp = keyPair as KeyPair;
    const data = new TextEncoder().encode('hello vericerts');
    const digest = keccak_256(data);

    const signature = await km.getSigner(secp.id).sign(data);
    expect(Array.from(recoverSecp256k1PublicKey(digest, signature, true))).toEqual(
      Array.from(secp.publicKey),
    );

    const raw = await km.signRawDigest(secp.id, digest);
    expect(Array.from(recoverSecp256k1PublicKey(digest, raw.signature, true))).toEqual(
      Array.from(secp.publicKey),
    );

    expect(km.getCredentialSigner(secp.id).alg).toBe('ES256K');
    expect(Array.from(getSecp256k1PublicKey(secp.privateKey, true))).toEqual(
      Array.from(secp.publicKey),
    );
  });
});

describe('署名経路は従来どおり動く（P-256）', () => {
  it('getCredentialSigner が ES256 の署名器を返し署名できる', async () => {
    const { km, keyPair } = await setup(CASES[1]?.derive as KeyPairCase['derive']);
    const signer = km.getCredentialSigner(keyPair.id);
    expect(signer.alg).toBe('ES256');
    expect((await signer.sign(new Uint8Array([1, 2, 3]))).length).toBe(64);
  });
});

describe.each(CASES)('$name はプロトタイプ汚染下でも封が効く', ({ derive, publicFields }) => {
  // `get` と `set` は同時に汚染しない（フィクスチャ自身の記述子リテラルが先に入れた `get` を継承して落ちる）。
  it.each([
    'get',
    'set',
  ])('Object.prototype.%s が関数で汚染されていても導出に成功し privateKey が列挙不可になる', async (accessor) => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await withPollutedPrototypeAsync({ [accessor]: () => undefined }, () =>
      derive(km),
    );
    expect(Object.getOwnPropertyDescriptor(keyPair, 'privateKey')).toMatchObject({
      enumerable: false,
      writable: false,
      configurable: false,
    });
    expect(Object.keys(keyPair)).toEqual([...publicFields]);
    expect(keyPair.privateKey.length).toBe(32);
  });
});

describe('Wallet.deriveKey は従来どおり privateKey を持たない', () => {
  it('戻りが 5 フィールドのみで、列挙不可の privateKey も持たず、JSON に出ない', async () => {
    const wallet = await createWallet({ storage: new MemoryStorage() });
    await wallet.importMnemonic(TEST_MNEMONIC);
    const result = await wallet.deriveKey(ETH_PATH);
    expect(Object.keys(result).sort()).toEqual(
      ['address', 'algorithm', 'derivationPath', 'id', 'publicKey'].sort(),
    );
    expect(Object.hasOwn(result, 'privateKey')).toBe(false);
    expect(Reflect.ownKeys(result)).not.toContain('privateKey');
    expect(JSON.stringify(result)).not.toContain('privateKey');
  });
});

describe('公開型の形は不変', () => {
  it('privateKey を含むオブジェクトリテラルが KeyPair / P256KeyPair として型検査を通る', () => {
    const privateKey = new Uint8Array(32);
    const publicKey = new Uint8Array(33);
    const secp: KeyPair = {
      id: 'id',
      algorithm: 'secp256k1',
      privateKey,
      publicKey,
      address: '0x0',
      derivationPath: 'm',
    };
    const p256: P256KeyPair = {
      id: 'id',
      algorithm: 'P-256',
      privateKey,
      publicKey,
      derivationPath: "m/0'",
    };
    expect(Object.keys(secp)).toContain('privateKey');
    expect(Object.keys(p256)).toContain('privateKey');
  });
});
