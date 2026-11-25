/**
 * 動的配列応答のデコード前検査。正規エンコード（ethers の `encodeFunctionResult`）だけを受理し、
 * 件数超過・長さワード偽装・offset 偽装・末尾余剰を、デコーダに渡す前に `1021` で拒否する。
 */

import { describe, expect, test } from 'bun:test';
import { Interface } from 'ethers';
import { assertArrayResponseWithin } from '../../array-response.js';

const iface = new Interface([
  'function a() view returns (address[])',
  'function u() view returns (uint256[])',
]);
const addr = (i: number): string => `0x${(i + 1).toString(16).padStart(40, '0')}`;
const word = (n: bigint): string => n.toString(16).padStart(64, '0');

describe('assertArrayResponseWithin', () => {
  test.each([0, 1, 15, 16])('address[] %d 件（上限 16）は受理する', (n) => {
    const raw = iface.encodeFunctionResult('a', [Array.from({ length: n }, (_, i) => addr(i))]);
    expect(() => assertArrayResponseWithin(raw, 16)).not.toThrow();
  });

  test.each([0, 1, 1024])('uint256[] %d 件（上限 1024）は受理する', (n) => {
    const raw = iface.encodeFunctionResult('u', [Array.from({ length: n }, (_, i) => BigInt(i))]);
    expect(() => assertArrayResponseWithin(raw, 1024)).not.toThrow();
  });

  // 上限 16 に対し、件数 × 実体サイズの異なる形状。
  test.each([
    [
      '上限 + 1 件',
      iface.encodeFunctionResult('a', [Array.from({ length: 17 }, (_, i) => addr(i))]),
    ],
    [
      '2,000 件',
      iface.encodeFunctionResult('a', [Array.from({ length: 2_000 }, (_, i) => addr(i))]),
    ],
    ['長さワードだけ 2^255', `0x${word(0x20n)}${word(2n ** 255n)}`],
    ['長さワードが 2^256 - 1', `0x${word(0x20n)}${'f'.repeat(64)}`],
    ['長さ 2 を主張して実体が 1 件', `0x${word(0x20n)}${word(2n)}${word(1n)}`],
    ['長さ 1 で末尾余剰', `0x${word(0x20n)}${word(1n)}${word(1n)}${word(0n)}`],
    ['offset 0x40', `0x${word(0x40n)}${word(0n)}${word(0n)}`],
    ['offset が巨大', `0x${word(2n ** 200n)}${word(0n)}`],
    ['空 0x', '0x'],
    ['1 ワードのみ', `0x${word(0x20n)}`],
    ['非 hex の長さワード', `0x${word(0x20n)}${'zz'.repeat(32)}`],
  ])('%s は 1021（phase: array_response_too_large）', (_label, raw) => {
    expect(() => assertArrayResponseWithin(raw, 16)).toThrow(
      expect.objectContaining({ code: '1021', context: { phase: 'array_response_too_large' } }),
    );
  });

  test('上限 0 は空配列のみ受理する', () => {
    expect(() => assertArrayResponseWithin(`0x${word(0x20n)}${word(0n)}`, 0)).not.toThrow();
    expect(() => assertArrayResponseWithin(`0x${word(0x20n)}${word(1n)}${word(0n)}`, 0)).toThrow();
  });
});
