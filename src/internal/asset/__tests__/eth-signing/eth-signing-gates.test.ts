/**
 * `eth-signing.ts` の署名 hex の `v` バイト・EIP-712 入力検証ゲート（fail-closed）・多次元 struct 配列の
 * encodeType。
 *
 * `ethers.verifyMessage` は `v >= 35` を parity へ正規化するため、`v` が 229/230 でも元アドレスへ
 * 復元できてしまう。標準の `ecrecover` / 厳密な検証器は `0x1b` / `0x1c` のみを受理するので、
 * 返却 hex の末尾バイトを直接検査する。
 */

import { describe, expect, test } from 'bun:test';
import { keccak256, TypedDataEncoder } from 'ethers';
import { formatEthereumSignature, typedDataV4Payload } from '../../eth-signing.js';
import { encodeType, type TypedData } from '../../eth-typed-data-types.js';

const ADDRESS = '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826';
const DOMAIN = { name: 'x', version: '1' };

/** ethers は可変配列の型定義を要求するため、readonly を外す。 */
function ethersTypes(typedData: TypedData): Record<string, { name: string; type: string }[]> {
  return Object.fromEntries(Object.entries(typedData.types).map(([k, v]) => [k, [...v]]));
}

function expectSignFailed(fn: () => unknown): void {
  try {
    fn();
    throw new Error('should have thrown');
  } catch (e) {
    expect((e as { code: string }).code).toBe('1020');
  }
}

/** 単一フィールド `v` を持つ struct の typedData。 */
function single(type: string, value: unknown, extra: TypedData['types'] = {}): TypedData {
  return {
    types: { ...extra, Item: [{ name: 'v', type }] },
    primaryType: 'Item',
    domain: DOMAIN,
    message: { v: value },
  };
}

describe('formatEthereumSignature の v バイト', () => {
  const rs = new Uint8Array(64).map((_, i) => i + 1);

  test.each([
    [0, '1b'],
    [1, '1c'],
  ])('recovery %i は v=0x%s（27/28）へ整形され r‖s は保持される', (recovery, vHex) => {
    const signature = formatEthereumSignature(Uint8Array.of(...rs, recovery));
    expect(signature).toHaveLength(2 + 130);
    expect(signature.slice(-2)).toBe(vHex);
    expect(signature.slice(0, -2)).toBe(
      `0x${Array.from(rs, (b) => b.toString(16).padStart(2, '0')).join('')}`,
    );
  });

  test('65 バイト以外（64 / 66）は 1020', () => {
    expectSignFailed(() => formatEthereumSignature(new Uint8Array(64)));
    expectSignFailed(() => formatEthereumSignature(new Uint8Array(66)));
  });
});

describe('typedDataV4Payload の入力検証ゲート', () => {
  const bytes = (n: number): string => `0x${'ab'.repeat(n)}`;
  const types = { Leaf: [{ name: 'x', type: 'uint256' }] };

  test.each([
    ['bytes4 に 5 バイト', single('bytes4', bytes(5))],
    ['bytes4 に 3 バイト', single('bytes4', bytes(3))],
    ['bytes4 に非 string', single('bytes4', 1234)],
    ['bytes33（幅超過）', single('bytes33', bytes(33))],
    ['bytes0（幅 0）', single('bytes0', '0x')],
    ['bytes に 0x 無し', single('bytes', 'abcd')],
    ['bytes に奇数桁 hex', single('bytes', '0xabc')],
    ['bytes に非 hex 文字', single('bytes', '0xzz')],
    ['bytes に非 string', single('bytes', 1)],
    ['string に非 string', single('string', 1)],
    ['address に 19 バイト', single('address', bytes(19))],
    ['address に 21 バイト', single('address', bytes(21))],
    ['address に非 string', single('address', 1)],
    ['address に 0x 無し', single('address', ADDRESS.slice(2))],
    ['bool に文字列', single('bool', 'true')],
    ['配列フィールドに非配列', single('uint256[]', 1)],
    ['配列フィールドに null', single('uint256[]', null)],
    ['固定長配列の要素数不足', single('uint256[2]', [1])],
    ['固定長配列の要素数超過', single('uint256[2]', [1, 2, 3])],
    ['多次元配列の内側が非配列', single('uint256[][]', [1])],
    ['struct フィールドに null', single('Leaf', null, types)],
    ['struct フィールドに非 object', single('Leaf', 'x', types)],
    ['フィールド無し struct に null', single('Empty', null, { Empty: [] })],
    ['struct 配列の要素に null', single('Leaf[]', [null], types)],
    ['未定義型', single('Undefined', {})],
    ['未対応の atomic 型名', single('float', 1)],
    [
      'primaryType が types に未定義',
      { types, primaryType: 'Missing', domain: DOMAIN, message: {} } as TypedData,
    ],
    ['domain が空', { types, primaryType: 'Leaf', domain: {}, message: { x: 1 } } as TypedData],
    [
      'domain に許容外フィールドのみ',
      { types, primaryType: 'Leaf', domain: { foo: 'bar' }, message: { x: 1 } } as TypedData,
    ],
  ])('%s は 1020', (_name, typedData) => {
    expectSignFailed(() => typedDataV4Payload(typedData));
  });

  test('encodeType: primaryType / 参照 struct が未定義なら 1020', () => {
    expectSignFailed(() => encodeType('Missing', {}));
  });

  test.each([
    ['bytes4 ちょうど 4 バイト', single('bytes4', bytes(4))],
    ['bytes32 ちょうど 32 バイト', single('bytes32', bytes(32))],
    ['bytes 空', single('bytes', '0x')],
    ['address 20 バイト', single('address', ADDRESS)],
    ['固定長配列 uint256[2]', single('uint256[2]', [1, 2])],
    ['空の動的配列', single('uint256[]', [])],
  ])('正例（%s）は ethers.TypedDataEncoder と一致する', (_name, typedData) => {
    const expected = TypedDataEncoder.hash(DOMAIN, ethersTypes(typedData), typedData.message);
    expect(keccak256(typedDataV4Payload(typedData))).toBe(expected);
  });
});

describe('struct の多次元配列の encodeType / ダイジェスト', () => {
  const A = [{ name: 'x', type: 'uint256' }];

  test.each([
    ['A[][]', [[{ x: 1 }, { x: 2 }], [{ x: 3 }]]],
    [
      'A[2][]',
      [
        [{ x: 1 }, { x: 2 }],
        [{ x: 3 }, { x: 4 }],
      ],
    ],
    ['A[][2]', [[{ x: 1 }], [{ x: 2 }, { x: 3 }]]],
    [
      'A[2][2]',
      [
        [{ x: 1 }, { x: 2 }],
        [{ x: 3 }, { x: 4 }],
      ],
    ],
    ['A[][][]', [[[{ x: 1 }], []], []]],
  ])('%s は要素 struct の定義を連結し、ethers と同じ typeHash / ダイジェストになる', (type, a) => {
    const allTypes = { A, M: [{ name: 'a', type }] };
    expect(encodeType('M', allTypes)).toBe(`M(${type} a)A(uint256 x)`);

    const typedData: TypedData = {
      types: allTypes,
      primaryType: 'M',
      domain: DOMAIN,
      message: { a },
    };
    expect(encodeType('M', allTypes)).toBe(new TypedDataEncoder(allTypes).encodeType('M'));
    expect(keccak256(typedDataV4Payload(typedData))).toBe(
      TypedDataEncoder.hash(DOMAIN, allTypes, { a }),
    );
  });

  test('異なる struct を多次元配列で参照すると名前昇順で全て連結される', () => {
    const allTypes = {
      A,
      B: [{ name: 'y', type: 'address' }],
      M: [
        { name: 'b', type: 'B[][]' },
        { name: 'a', type: 'A[2][]' },
      ],
    };
    expect(encodeType('M', allTypes)).toBe('M(B[][] b,A[2][] a)A(uint256 x)B(address y)');
    expect(encodeType('M', allTypes)).toBe(new TypedDataEncoder(allTypes).encodeType('M'));
  });

  test('プリミティブの多次元配列は struct 定義を連結しない', () => {
    const allTypes = { M: [{ name: 'a', type: 'uint256[][]' }] };
    expect(encodeType('M', allTypes)).toBe('M(uint256[][] a)');
  });
});
