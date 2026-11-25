/**
 * `typedDataV4Payload` のフィールド型文字列長の上限。
 *
 * 多次元配列の `[]` を 1 個ずつ剥がす処理は型文字列長に対して二次になり、500 KB の型 1 つで署名計算が 21〜27 秒
 * 停止した。実時間ではなく「`parseArrayType` が文字列を走査する量の上限（`MAX_FIELD_TYPE_CHARS`）」で pin する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { encodeType, typedDataV4Payload } from '../../eth-signing.js';
import {
  MAX_FIELD_TYPE_CHARS,
  parseArrayType,
  type TypedData,
} from '../../eth-typed-data-types.js';

function withFieldType(type: string, value: unknown): TypedData {
  return {
    types: { Root: [{ name: 'f', type }] },
    primaryType: 'Root',
    domain: { name: 'x' },
    message: { f: value },
  };
}

function nestedArray(depth: number): unknown {
  let value: unknown = [];
  for (let i = 1; i < depth; i++) value = [value];
  return value;
}

describe('parseArrayType', () => {
  test.each([
    ['Foo[]', 'Foo', undefined],
    ['Foo[3]', 'Foo', 3],
    ['Foo[][2]', 'Foo[]', 2],
    ['uint256[2][]', 'uint256[2]', undefined],
  ])('%s は要素型 %s・長さ %p', (type, elementType, length) => {
    expect(parseArrayType(type)).toEqual({ elementType, length });
  });

  test.each([
    'Foo',
    '[]',
    'Foo[x]',
    'Foo[',
    'Foo]',
    'Foo[-1]',
    '',
  ])('配列型でない %p は null', (type) => {
    expect(parseArrayType(type)).toBeNull();
  });

  test('上限ちょうどの長さは受理し、1 文字超えると 1020 で拒否する', () => {
    const atLimit = `${'A'.repeat(MAX_FIELD_TYPE_CHARS - 2)}[]`;
    expect(parseArrayType(atLimit)?.elementType.length).toBe(MAX_FIELD_TYPE_CHARS - 2);
    expect(() => parseArrayType(`${atLimit}x`)).toThrow(VericertsError);
    expect(() => parseArrayType('A'.repeat(MAX_FIELD_TYPE_CHARS + 1))).toThrow(
      new VericertsError(ErrorCodes.SIGN_FAILED),
    );
  });
});

describe('typedDataV4Payload: 型文字列長の上限', () => {
  test('500 KB の `[]` 連結型は署名計算の前に 1020 で拒否する', () => {
    const type = `uint256${'[]'.repeat(250_000)}`;
    expect(() => typedDataV4Payload(withFieldType(type, []))).toThrow(VericertsError);
    expect(() => encodeType('Root', { Root: [{ name: 'f', type }] })).toThrow(VericertsError);
  });

  test('正規の多次元配列（深さ 100）は署名できる', () => {
    const type = `uint256${'[]'.repeat(100)}`;
    expect(typedDataV4Payload(withFieldType(type, nestedArray(100))).length).toBe(2 + 32 + 32);
  });
});
