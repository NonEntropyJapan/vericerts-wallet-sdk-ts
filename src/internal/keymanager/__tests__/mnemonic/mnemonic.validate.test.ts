import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { assertValidMnemonic, isValidMnemonic } from '../../mnemonic.js';

/** BIP-39 公式テストベクトル（英語 12 語、エントロピーオール 0）。 */
const OFFICIAL_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** BIP-39 公式テストベクトル（英語 24 語、エントロピーオール 0）。 */
const OFFICIAL_24 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

/** BIP-39 公式テストベクトル（英語 15 語、エントロピーオール 0）。本 SDK では拒否対象。 */
const OFFICIAL_15 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent';

describe('isValidMnemonic', () => {
  test('BIP-39 公式ベクトル（12 語）は true', () => {
    expect(isValidMnemonic(OFFICIAL_12)).toBe(true);
  });

  test('BIP-39 公式ベクトル（24 語）は true', () => {
    expect(isValidMnemonic(OFFICIAL_24)).toBe(true);
  });

  test('言語を明示しても妥当（en）', () => {
    expect(isValidMnemonic(OFFICIAL_12, 'en')).toBe(true);
  });

  test('ワードリスト外の単語が混入すると false', () => {
    const words = OFFICIAL_12.split(' ');
    words[0] = 'notabip39word';
    expect(isValidMnemonic(words.join(' '))).toBe(false);
  });

  test('チェックサム不正（末尾語を別の有効語に差し替え）は false', () => {
    // 末尾 'about' を別のワードリスト内単語 'zoo' に差し替えるとチェックサムが崩れる。
    const words = OFFICIAL_12.split(' ');
    words[words.length - 1] = 'zoo';
    expect(isValidMnemonic(words.join(' '))).toBe(false);
  });

  test('15 語の有効 BIP-39 は本 SDK 制約で false', () => {
    // @scure 単体では妥当だが、本 SDK は 12 / 24 語のみ許可する。
    expect(isValidMnemonic(OFFICIAL_15)).toBe(false);
  });

  test('空文字は false', () => {
    expect(isValidMnemonic('')).toBe(false);
  });
});

describe('assertValidMnemonic', () => {
  test('妥当なニーモニックでは例外を投げない', () => {
    expect(() => assertValidMnemonic(OFFICIAL_12)).not.toThrow();
  });

  test('不正入力で INVALID_MNEMONIC（code 1001）を投げる', () => {
    let caught: unknown;
    try {
      assertValidMnemonic(OFFICIAL_15);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.INVALID_MNEMONIC);
  });

  test('例外メッセージにニーモニック本文を含めない', () => {
    let caught: unknown;
    try {
      assertValidMnemonic(OFFICIAL_15);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    const message = (caught as VericertsError).message;
    // 秘密を含まない静的な日本語メッセージ。
    expect(message).toBe('BIP-39 ニーモニックが不正です');
    // ニーモニックを構成する語が一切含まれていないこと。
    for (const word of OFFICIAL_15.split(' ')) {
      expect(message).not.toContain(word);
    }
  });
});
