import { describe, expect, test } from 'bun:test';
import { entropyToMnemonic, type MnemonicLanguage, mnemonicToEntropy } from '../../mnemonic.js';

/** ラウンドトリップ検証対象の全 10 言語。 */
const LANGUAGES: MnemonicLanguage[] = [
  'en',
  'ja',
  'ko',
  'zh-CN',
  'zh-TW',
  'es',
  'fr',
  'it',
  'cs',
  'pt',
];

/** 128bit（16 バイト）と 256bit（32 バイト）のエントロピー長。 */
const ENTROPY_BYTE_LENGTHS = [16, 32] as const;

describe('entropy ラウンドトリップ', () => {
  for (const language of LANGUAGES) {
    for (const byteLength of ENTROPY_BYTE_LENGTHS) {
      const bits = byteLength * 8;
      test(`${language} / ${bits}bit: entropy → mnemonic → entropy が一致`, () => {
        const entropy = new Uint8Array(byteLength);
        crypto.getRandomValues(entropy);

        const mnemonic = entropyToMnemonic(entropy, language);
        const recovered = mnemonicToEntropy(mnemonic, language);

        expect(recovered).toEqual(entropy);
      });

      test(`${language} / ${bits}bit: 言語自動判定でも一致`, () => {
        const entropy = new Uint8Array(byteLength);
        crypto.getRandomValues(entropy);

        const mnemonic = entropyToMnemonic(entropy, language);
        // language を省略して自動判定経路を通す。
        const recovered = mnemonicToEntropy(mnemonic);

        expect(recovered).toEqual(entropy);
      });
    }
  }
});
