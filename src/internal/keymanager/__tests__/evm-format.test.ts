import { describe, expect, test } from 'bun:test';
import { isValidEvmAddress } from '../../evm-format.js';

// EIP-55 の公式テストベクタ（https://eips.ethereum.org/EIPS/eip-55）。
const CHECKSUMMED = [
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
  '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
];

describe('isValidEvmAddress', () => {
  test.each(CHECKSUMMED)('EIP-55 チェックサム一致の混在表記を受理する: %s', (address) => {
    expect(isValidEvmAddress(address)).toBe(true);
  });

  test.each(
    CHECKSUMMED,
  )('全小文字・全大文字（チェックサム情報なし）は従来どおり受理する: %s', (address) => {
    expect(isValidEvmAddress(address.toLowerCase())).toBe(true);
    expect(isValidEvmAddress(`0x${address.slice(2).toUpperCase()}`)).toBe(true);
  });

  test.each(CHECKSUMMED)('混在表記で 1 文字の大小を反転したアドレスは拒否する: %s', (address) => {
    const body = address.slice(2);
    const index = [...body].findIndex((ch) => /[a-f]/i.test(ch));
    const flipped = body.slice(0, index) + swapCase(body.charAt(index)) + body.slice(index + 1);
    expect(isValidEvmAddress(`0x${flipped}`)).toBe(false);
  });

  test('形式不正（長さ・hex 外・0x なし・非文字列）は拒否する', () => {
    expect(isValidEvmAddress('0x1234')).toBe(false);
    expect(isValidEvmAddress(`0x${'g'.repeat(40)}`)).toBe(false);
    expect(isValidEvmAddress('5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')).toBe(false);
    expect(isValidEvmAddress(undefined)).toBe(false);
  });
});

function swapCase(ch: string): string {
  return ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase();
}
