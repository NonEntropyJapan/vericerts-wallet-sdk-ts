/**
 * `eth-signing.ts`（`personal_sign` / `eth_signTypedData_v4` の署名対象バイト列組み立てと署名 hex
 * 整形）の統合テスト。
 *
 * 独自実装を独自実装で検証すると往復バグを見逃すため、参照実装として ethers を用いる:
 * - `personal_sign`: `Signer.sign(personalSignPayload(data))` を整形した署名を、
 *   `ethers.verifyMessage` が同じ signer アドレスへ復元できることを確認する。
 * - `eth_signTypedData_v4`: 同様に `ethers.verifyTypedData` で検証する。加えて EIP-712 の公式
 *   Example（Mail 構造体、eips.ethereum.org/EIPS/eip-712）のダイジェストが
 *   `ethers.TypedDataEncoder.hash` と完全一致することも確認する。
 */

import { describe, expect, test } from 'bun:test';
import { keccak256, TypedDataEncoder, verifyMessage, verifyTypedData } from 'ethers';
import { ErrorCodes } from '../../../errors.js';
import { KeyManager } from '../../../keymanager/keymanager.js';
import {
  formatEthereumSignature,
  personalSignPayload,
  typedDataV4Payload,
} from '../../eth-signing.js';
import type { TypedData } from '../../eth-typed-data-types.js';

const TEST_MNEMONIC = 'test test test test test test test test test test test junk';
const ETH_PATH = "m/44'/60'/0'/0/0";

describe('personalSignPayload + formatEthereumSignature（ERC-191）', () => {
  test('hex データの署名を ethers.verifyMessage が同じアドレスへ復元する', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const signer = km.getSigner(keyPair.id);

    const dataHex = '0xdeadbeef';
    const signature = await signer.sign(personalSignPayload(dataHex));
    const hexSignature = formatEthereumSignature(signature);

    const recovered = verifyMessage(new Uint8Array([0xde, 0xad, 0xbe, 0xef]), hexSignature);
    expect(recovered.toLowerCase()).toBe(signer.address().toLowerCase());
  });

  test('非 hex（生テキスト）データは UTF-8 メッセージとして扱われる', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const signer = km.getSigner(keyPair.id);

    const text = 'Hello, VeriCerts!';
    const signature = await signer.sign(personalSignPayload(text));
    const hexSignature = formatEthereumSignature(signature);

    const recovered = verifyMessage(text, hexSignature);
    expect(recovered.toLowerCase()).toBe(signer.address().toLowerCase());
  });

  test('formatEthereumSignature は 65 バイトでない署名を拒否する', () => {
    expect(() => formatEthereumSignature(new Uint8Array(64))).toThrow();
  });

  // ES256K-R の JWS 署名は signing-input への EIP-191 署名と同一。personal_sign が通すと dApp が DID の署名を偽造できる。
  test('alg が ES256K-R の JWS signing-input は text / hex のどちらでも拒否する（SIGN_FAILED）', () => {
    const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const signingInput = `${segment({ alg: 'ES256K-R', kid: 'did:pkh:eip155:1:0xabc#blockchainAccountId' })}.${segment({ iss: 'did:pkh:eip155:1:0xabc' })}`;
    const asHex = `0x${Buffer.from(signingInput).toString('hex')}`;
    for (const data of [signingInput, asHex]) {
      expect(() => personalSignPayload(data)).toThrow(
        expect.objectContaining({ code: ErrorCodes.SIGN_FAILED }),
      );
    }
    // ヘッダを大きく水増しした signing-input でも拒否する（検証側 `decodeCompactJws` にヘッダ長の上限は無い）。
    const padded = `${segment({ alg: 'ES256K-R', pad: 'A'.repeat(5000) })}.${segment({ iss: 'did:pkh:eip155:1:0xabc' })}`;
    for (const data of [padded, `0x${Buffer.from(padded).toString('hex')}`]) {
      expect(() => personalSignPayload(data)).toThrow(
        expect.objectContaining({ code: ErrorCodes.SIGN_FAILED }),
      );
    }
    // 通常のメッセージ・標準の alg の JWS は従来どおり署名できる（ES256K の signing-input は SHA-256 の別ドメイン）。
    expect(() => personalSignPayload('Hello')).not.toThrow();
    expect(() =>
      personalSignPayload(`${segment({ alg: 'ES256K' })}.${segment({ iss: 'did:example:1' })}`),
    ).not.toThrow();
  });
});

describe('typedDataV4Payload（EIP-712）', () => {
  const types = {
    Person: [
      { name: 'name', type: 'string' },
      { name: 'wallet', type: 'address' },
    ],
    Mail: [
      { name: 'from', type: 'Person' },
      { name: 'to', type: 'Person' },
      { name: 'contents', type: 'string' },
    ],
  };
  const domain = {
    name: 'Ether Mail',
    version: '1',
    chainId: 1,
    verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
  };
  const message = {
    from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
    to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
    contents: 'Hello, Bob!',
  };
  const typedData: TypedData = { types, primaryType: 'Mail', domain, message };

  test('署名を ethers.verifyTypedData が同じアドレスへ復元する', async () => {
    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const signer = km.getSigner(keyPair.id);

    const signature = await signer.sign(typedDataV4Payload(typedData));
    const hexSignature = formatEthereumSignature(signature);

    const recovered = verifyTypedData(domain, types, message, hexSignature);
    expect(recovered.toLowerCase()).toBe(signer.address().toLowerCase());
  });

  test('EIP-712 公式 Example のダイジェストが ethers.TypedDataEncoder.hash と完全一致する', () => {
    // eips.ethereum.org/EIPS/eip-712 の Mail Example（domain/types/message）に対する最終ダイジェスト
    // keccak256(typedDataV4Payload) が、ethers の参照実装（TypedDataEncoder.hash）と一致することを
    // 直接検証する。
    const digest = keccak256(Buffer.from(typedDataV4Payload(typedData)));
    const expectedDigest = TypedDataEncoder.hash(domain, types, message);
    expect(digest).toBe(expectedDigest);
  });

  test('配列フィールド（Type[]）も ethers.verifyTypedData と一致する', async () => {
    const arrayTypes = {
      Item: [
        { name: 'id', type: 'uint256' },
        { name: 'label', type: 'string' },
      ],
      Basket: [
        { name: 'owner', type: 'address' },
        { name: 'items', type: 'Item[]' },
      ],
    };
    const arrayDomain = { name: 'Basket App', version: '1', chainId: 1 };
    const arrayMessage = {
      owner: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
      items: [
        { id: 1n, label: 'apple' },
        { id: 2n, label: 'banana' },
      ],
    };
    const arrayTypedData: TypedData = {
      types: arrayTypes,
      primaryType: 'Basket',
      domain: arrayDomain,
      message: arrayMessage,
    };

    const km = new KeyManager();
    await km.importMnemonic(TEST_MNEMONIC);
    const keyPair = await km.deriveKey(ETH_PATH);
    const signer = km.getSigner(keyPair.id);

    const signature = await signer.sign(typedDataV4Payload(arrayTypedData));
    const hexSignature = formatEthereumSignature(signature);

    const recovered = verifyTypedData(arrayDomain, arrayTypes, arrayMessage, hexSignature);
    expect(recovered.toLowerCase()).toBe(signer.address().toLowerCase());
  });

  test('未対応型・未定義 struct 参照は 1020 に正規化する', () => {
    const badTypedData: TypedData = {
      types: { Foo: [{ name: 'bar', type: 'Undefined' }] },
      primaryType: 'Foo',
      domain: { name: 'x', version: '1' },
      message: { bar: {} },
    };
    try {
      typedDataV4Payload(badTypedData);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1020');
    }
  });

  test('0x プレフィックス無しの address フィールドは 1020 で拒否する', () => {
    const noPrefixTypedData: TypedData = {
      types,
      primaryType: 'Mail',
      domain,
      message: {
        from: { name: 'Cow', wallet: 'CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
        to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
        contents: 'Hello, Bob!',
      },
    };
    try {
      typedDataV4Payload(noPrefixTypedData);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1020');
    }
  });

  test('0x プレフィックス無しの bytesN フィールドは 1020 で拒否する', () => {
    const bytesTypedData: TypedData = {
      types: { Item: [{ name: 'data', type: 'bytes32' }] },
      primaryType: 'Item',
      domain: { name: 'x', version: '1' },
      message: { data: 'aa'.repeat(32) },
    };
    try {
      typedDataV4Payload(bytesTypedData);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as { code: string }).code).toBe('1020');
    }
  });
  describe('uintN/intN の範囲・bool の厳格検証', () => {
    const digestOf = (type: string, value: unknown): string =>
      keccak256(
        Buffer.from(
          typedDataV4Payload({
            types: { Item: [{ name: 'v', type }] },
            primaryType: 'Item',
            domain: { name: 'x', version: '1' },
            message: { v: value },
          }),
        ),
      );
    const ethersDigest = (type: string, value: unknown): string =>
      TypedDataEncoder.hash(
        { name: 'x', version: '1' },
        { Item: [{ name: 'v', type }] },
        { v: value },
      );
    const code = (fn: () => unknown): string | undefined => {
      try {
        fn();
      } catch (e) {
        return (e as { code?: string }).code;
      }
      return undefined;
    };

    test.each([
      ['uint256', 2n ** 256n + 5n],
      ['uint256', 1.9],
      ['uint256', ''],
      ['uint256', '  5'],
      ['uint256', Number.MAX_SAFE_INTEGER + 2],
      ['uint256', Number.NaN],
      ['uint8', 300],
      ['uint8', -1],
      ['int8', 200],
      ['int8', -129],
      ['uint7', 1],
      ['uint0', 0],
      ['uint264', 1],
      ['bool', 'true'],
      ['bool', 1],
      ['bool', undefined],
    ])('%s に不正値 %p は 1020 で拒否する', (type, value) => {
      expect(code(() => digestOf(type, value))).toBe('1020');
    });

    test.each([
      ['uint256', 5],
      ['uint256', '0x10'],
      ['uint256', 2n ** 256n - 1n],
      ['uint8', 255],
      ['int8', -128],
      ['int8', 127],
      ['int256', -1n],
      ['int256', '-5'],
      ['bool', true],
      ['bool', false],
    ])('%s の正常値 %p は ethers と同一ダイジェスト', (type, value) => {
      expect(digestOf(type, value)).toBe(ethersDigest(type, value));
    });

    test.each([
      ['uint256[2]', [1, 2, 3]],
      ['uint256[2]', [1]],
      ['uint256[2]', []],
      ['uint256[0]', [1]],
      ['uint256[2][2]', [[1, 2]]],
      ['uint256[2][2]', [[1, 2], [3]]],
    ])('固定長配列 %s に長さ不一致 %p は 1020 で拒否する', (type, value) => {
      expect(code(() => digestOf(type, value))).toBe('1020');
    });

    test.each([
      ['uint256[2]', [1, 2]],
      ['uint256[0]', []],
      [
        'uint256[2][2]',
        [
          [1, 2],
          [3, 4],
        ],
      ],
      ['uint256[]', [1, 2, 3]],
      ['uint256[]', []],
    ])('配列 %s の正常値 %p は ethers と同一ダイジェスト', (type, value) => {
      expect(digestOf(type, value)).toBe(ethersDigest(type, value));
    });
  });
});
