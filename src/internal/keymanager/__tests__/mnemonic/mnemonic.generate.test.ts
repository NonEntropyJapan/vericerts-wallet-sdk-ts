import { describe, expect, test } from 'bun:test';
import { wordlist as japaneseWordlist } from '@scure/bip39/wordlists/japanese.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { generateMnemonic, isValidMnemonic, type WordCount } from '../../mnemonic.js';

describe('generateMnemonic', () => {
  test('12 語のニーモニックを生成する', () => {
    const mnemonic = generateMnemonic(12);
    expect(mnemonic.trim().split(/\s+/)).toHaveLength(12);
  });

  test('24 語のニーモニックを生成する', () => {
    const mnemonic = generateMnemonic(24);
    expect(mnemonic.trim().split(/\s+/)).toHaveLength(24);
  });

  test('生成結果は isValidMnemonic で true になる（12 語）', () => {
    expect(isValidMnemonic(generateMnemonic(12))).toBe(true);
  });

  test('生成結果は isValidMnemonic で true になる（24 語）', () => {
    expect(isValidMnemonic(generateMnemonic(24))).toBe(true);
  });

  test('言語指定（ja）生成の語はすべて日本語ワードリストに含まれる', () => {
    const mnemonic = generateMnemonic(12, 'ja');
    const words = mnemonic.trim().split(/\s+/);
    expect(words).toHaveLength(12);
    for (const word of words) {
      expect(japaneseWordlist).toContain(word);
    }
  });

  test('ja 生成結果は language=ja で妥当', () => {
    expect(isValidMnemonic(generateMnemonic(12, 'ja'), 'ja')).toBe(true);
  });

  test('不正な語数（15）は INVALID_WORD_COUNT（code 1002）を投げる', () => {
    let caught: unknown;
    try {
      generateMnemonic(15 as WordCount);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_WORD_COUNT);
  });

  test('不正な語数（0）は INVALID_WORD_COUNT（code 1002）を投げる', () => {
    let caught: unknown;
    try {
      generateMnemonic(0 as WordCount);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_WORD_COUNT);
  });

  // non-functional 要件「ニーモニック生成 < 100ms」の回帰検知。
  // 実測は sub-ms のため、フレーク耐性を持たせて余裕のある 100ms を閾値とする（約 100x マージン）。
  test('24 語の生成は 100ms 未満で完了する（non-functional 性能要件）', () => {
    const start = performance.now();
    generateMnemonic(24);
    const elapsedMs = performance.now() - start;
    expect(elapsedMs).toBeLessThan(100);
  });
});
