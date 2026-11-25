/**
 * `typedDataV4Payload` の typeHash メモ化。
 *
 * struct インスタンスごとに `typeHash`（`types` の総サイズに比例）を再計算すると、処理量が
 * (types サイズ) × (インスタンス数) の二次になり、512 KiB 内の typed data で署名計算が数十秒停止した。
 * 実時間ではなく keccak256 の呼び出し回数（決定的カウンタ）で、型ごと 1 回しか計算しないことを pin し、
 * ダイジェストが参照実装（ethers）と一致することも確かめる。
 */

import { describe, expect, spyOn, test } from 'bun:test';
import { keccak256, TypedDataEncoder } from 'ethers';
import * as addressModule from '../../../keymanager/address.js';
import { typedDataV4Payload } from '../../eth-signing.js';
import { MAX_TYPE_ENCODE_CHARS, type TypedData } from '../../eth-typed-data-types.js';

const DOMAIN = { name: 'x' };

/** `Item { leaf: Leaf, n: uint256 }` を `count` 個並べた Root。Item / Leaf の 2 種類の struct インスタンスが並ぶ。 */
function nested(count: number): TypedData {
  return {
    types: {
      Leaf: [{ name: 'v', type: 'uint256' }],
      Item: [
        { name: 'leaf', type: 'Leaf' },
        { name: 'n', type: 'uint256' },
      ],
      Root: [{ name: 'items', type: 'Item[]' }],
    },
    primaryType: 'Root',
    domain: DOMAIN,
    message: {
      items: Array.from({ length: count }, (_, i) => ({ leaf: { v: i }, n: i })),
    },
  };
}

function keccakCalls(typedData: TypedData): number {
  const spy = spyOn(addressModule, 'keccak256');
  try {
    typedDataV4Payload(typedData);
    return spy.mock.calls.length;
  } finally {
    spy.mockRestore();
  }
}

describe('typedDataV4Payload: typeHash は型ごとに 1 回だけ計算する', () => {
  test('インスタンスを 1 つ増やすたびの keccak256 は hashStruct ぶんだけ（Item + Leaf の 2 回）', () => {
    // typeHash が毎回再計算されるなら、1 インスタンスあたりの増分は 4 回（hashStruct 2 + typeHash 2）になる。
    expect(keccakCalls(nested(150)) - keccakCalls(nested(50))).toBe(100 * 2);
  });

  test('struct 型が 1 種類でもインスタンス数に対し線形（型ごと 1 回）', () => {
    const typedData = (count: number): TypedData => ({
      types: { Item: [{ name: 'n', type: 'uint256' }], Root: [{ name: 'items', type: 'Item[]' }] },
      primaryType: 'Root',
      domain: DOMAIN,
      message: { items: Array.from({ length: count }, (_, i) => ({ n: i })) },
    });
    expect(keccakCalls(typedData(300)) - keccakCalls(typedData(100))).toBe(200);
  });

  test('メモ化してもダイジェストは参照実装（ethers TypedDataEncoder）と一致する', () => {
    const { types, message } = nested(40);
    const mutableTypes = Object.fromEntries(Object.entries(types).map(([k, v]) => [k, [...v]]));
    const payload = typedDataV4Payload(nested(40));
    expect(keccak256(payload)).toBe(TypedDataEncoder.hash(DOMAIN, mutableTypes, message));
  });

  test('同じ型を複数の経路から参照しても（配列・入れ子・ダイヤモンド）ダイジェストは一致する', () => {
    const typedData: TypedData = {
      types: {
        Leaf: [{ name: 'id', type: 'uint256' }],
        Mid: [
          { name: 'leaf', type: 'Leaf' },
          { name: 'leaves', type: 'Leaf[]' },
        ],
        Root: [
          { name: 'a', type: 'Mid' },
          { name: 'b', type: 'Mid[2]' },
          { name: 'c', type: 'Leaf' },
        ],
      },
      primaryType: 'Root',
      domain: DOMAIN,
      message: {
        a: { leaf: { id: 1 }, leaves: [{ id: 2 }] },
        b: [
          { leaf: { id: 3 }, leaves: [] },
          { leaf: { id: 4 }, leaves: [{ id: 5 }, { id: 6 }] },
        ],
        c: { id: 7 },
      },
    };
    const mutableTypes = Object.fromEntries(
      Object.entries(typedData.types).map(([k, v]) => [k, [...v]]),
    );
    expect(keccak256(typedDataV4Payload(typedData))).toBe(
      TypedDataEncoder.hash(DOMAIN, mutableTypes, typedData.message),
    );
  });

  describe('型が連なって typeHash の総量が O(N²) になる入力', () => {
    /** T0 → T1 → … → T{N-1}。全型のインスタンスが入れ子で存在し、各 typeHash が残りの型すべてを含む。 */
    function chain(length: number): TypedData {
      const types: Record<string, { name: string; type: string }[]> = {};
      for (let i = 0; i < length; i++) {
        const last = i === length - 1;
        types[`T${i}`] = [{ name: last ? 'v' : 'next', type: last ? 'uint256' : `T${i + 1}` }];
      }
      types.Root = [{ name: 'x', type: 'T0' }];
      let leaf: Record<string, unknown> = { v: 1 };
      for (let i = length - 2; i >= 0; i--) leaf = { next: leaf };
      return { types, primaryType: 'Root', domain: DOMAIN, message: { x: leaf } };
    }

    test('encodeType の総量が予算を超えたら署名せず拒否する（1020）', () => {
      // 1,500 型の総量は約 2,200 万文字 > MAX_TYPE_ENCODE_CHARS。
      expect(() => typedDataV4Payload(chain(1500))).toThrow(
        expect.objectContaining({ code: '1020' }),
      );
    });

    test('予算内の連鎖は従来どおり署名でき、ethers と一致する', () => {
      // 100 型の総量は約 11 万文字。
      const typedData = chain(100);
      const mutableTypes = Object.fromEntries(
        Object.entries(typedData.types).map(([k, v]) => [k, [...v]]),
      );
      expect(keccak256(typedDataV4Payload(typedData))).toBe(
        TypedDataEncoder.hash(DOMAIN, mutableTypes, typedData.message),
      );
      expect(MAX_TYPE_ENCODE_CHARS).toBeGreaterThan(200_000);
    });
  });
});
