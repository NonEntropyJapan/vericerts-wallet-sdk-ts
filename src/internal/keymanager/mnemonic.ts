/**
 * BIP-39 ニーモニックの純粋関数モジュール。
 *
 * `@scure/bip39` をラップし、本 SDK の制約（12 / 24 語のみ許可、10 言語サポート）を
 * 適用する。状態を持たない純粋関数のみを公開する。
 *
 * セキュリティ上の注意:
 * - ニーモニック本文やエントロピーなどの秘密情報は、例外メッセージやログに
 *   一切含めない。
 * - エラーは `VericertsError` を投げる。メッセージは
 *   秘密を含まない静的な日本語で、code により分岐できる。
 */

import {
  entropyToMnemonic as scureEntropyToMnemonic,
  generateMnemonic as scureGenerateMnemonic,
  mnemonicToEntropy as scureMnemonicToEntropy,
  validateMnemonic as scureValidateMnemonic,
} from '@scure/bip39';
import { wordlist as czechWordlist } from '@scure/bip39/wordlists/czech.js';
import { wordlist as englishWordlist } from '@scure/bip39/wordlists/english.js';
import { wordlist as frenchWordlist } from '@scure/bip39/wordlists/french.js';
import { wordlist as italianWordlist } from '@scure/bip39/wordlists/italian.js';
import { wordlist as japaneseWordlist } from '@scure/bip39/wordlists/japanese.js';
import { wordlist as koreanWordlist } from '@scure/bip39/wordlists/korean.js';
import { wordlist as portugueseWordlist } from '@scure/bip39/wordlists/portuguese.js';
import { wordlist as simplifiedChineseWordlist } from '@scure/bip39/wordlists/simplified-chinese.js';
import { wordlist as spanishWordlist } from '@scure/bip39/wordlists/spanish.js';
import { wordlist as traditionalChineseWordlist } from '@scure/bip39/wordlists/traditional-chinese.js';
import { ErrorCodes, VericertsError } from '../errors.js';

/** サポートする BIP-39 ニーモニック言語。 */
export type MnemonicLanguage =
  | 'en'
  | 'ja'
  | 'ko'
  | 'zh-CN'
  | 'zh-TW'
  | 'es'
  | 'fr'
  | 'it'
  | 'cs'
  | 'pt';

/** 本 SDK が許可するニーモニックの語数。 */
export type WordCount = 12 | 24;

/**
 * 言語コードから `@scure/bip39` のワードリストへの静的マッピング。
 * 自動判定の総当りでも参照順を一定に保つため、`en` を先頭に置く。
 */
const WORDLISTS: Record<MnemonicLanguage, string[]> = {
  en: englishWordlist,
  ja: japaneseWordlist,
  ko: koreanWordlist,
  'zh-CN': simplifiedChineseWordlist,
  'zh-TW': traditionalChineseWordlist,
  es: spanishWordlist,
  fr: frenchWordlist,
  it: italianWordlist,
  cs: czechWordlist,
  pt: portugueseWordlist,
};

/** 自動判定で総当りする言語の順序。 */
const ALL_LANGUAGES = Object.keys(WORDLISTS) as MnemonicLanguage[];

/** 語数 → BIP-39 エントロピー強度（bit）のマッピング。 */
const STRENGTH_BY_WORD_COUNT: Record<WordCount, number> = {
  12: 128,
  24: 256,
};

/**
 * ニーモニックを空白で分割した語数を返す。
 * 前後の空白を除去し、連続する空白も 1 区切りとして扱う。
 */
function countWords(mnemonic: string): number {
  const trimmed = mnemonic.trim();
  if (trimmed.length === 0) {
    return 0;
  }
  return trimmed.split(/\s+/).length;
}

/** 語数が本 SDK で許可された 12 / 24 のいずれかかを判定する。 */
function hasAllowedWordCount(mnemonic: string): boolean {
  const count = countWords(mnemonic);
  return count === 12 || count === 24;
}

/**
 * 指定言語のワードリストを返す。
 * @throws 未登録の言語が渡された場合（型上は到達しないランタイム防御）。
 */
function getWordlist(language: MnemonicLanguage): string[] {
  const wordlist = WORDLISTS[language];
  if (wordlist === undefined) {
    // これは型保証により到達しない防御。未登録言語に対する保険であり、
    // `MnemonicLanguage` union 外の値が渡らない限り発生しない。
    // 未対応言語にもニーモニックの入力エラーコードを使う。
    throw new VericertsError(ErrorCodes.INVALID_MNEMONIC);
  }
  return wordlist;
}

/**
 * 新規 BIP-39 ニーモニックを生成する。
 *
 * @param wordCount 生成する語数（12 または 24）。
 * @param language 使用する言語。省略時は英語（`en`）。
 * @returns 空白区切りのニーモニック文字列。
 * @throws `wordCount` が 12 / 24 以外の場合（VericertsError、code `1002`）。
 */
export function generateMnemonic(wordCount: WordCount, language: MnemonicLanguage = 'en'): string {
  const strength = STRENGTH_BY_WORD_COUNT[wordCount];
  if (strength === undefined) {
    throw new VericertsError(ErrorCodes.INVALID_WORD_COUNT);
  }
  return scureGenerateMnemonic(getWordlist(language), strength);
}

/**
 * ニーモニックが本 SDK の制約を満たし、かつ BIP-39 として妥当かを判定する。
 *
 * 12 / 24 語以外（15 / 18 / 21 語など）は、BIP-39 として正当でも `false` を返す。
 *
 * 注意（自動判定の曖昧性）: `language` を省略すると 10 言語を総当りで判定する。
 * 英語とフランス語のワードリストは約 100 語を共有しており、共有語のみで
 * 構成されたニーモニックは自動判定で意図と異なる言語に解決され得る。
 * （判定結果そのものは BIP-39 として健全だが、言語は一意に定まらない。）
 * 言語を確実に区別したい場合は `language` 引数を明示すること。
 *
 * @param mnemonic 検証対象のニーモニック。
 * @param language 言語。省略時は 10 言語を総当りで自動判定する（上記の曖昧性に注意）。
 * @returns 妥当なら `true`、不正なら `false`。
 */
export function isValidMnemonic(mnemonic: string, language?: MnemonicLanguage): boolean {
  if (!hasAllowedWordCount(mnemonic)) {
    return false;
  }
  if (language !== undefined) {
    return scureValidateMnemonic(mnemonic, getWordlist(language));
  }
  return ALL_LANGUAGES.some((lang) => scureValidateMnemonic(mnemonic, WORDLISTS[lang]));
}

/**
 * ニーモニックが妥当であることを表明する。不正なら例外を投げる。
 *
 * @param mnemonic 検証対象のニーモニック。
 * @param language 言語。省略時は自動判定。
 * @throws 不正な場合（VericertsError、code `1001`）。メッセージにニーモニック本文は含めない。
 */
export function assertValidMnemonic(mnemonic: string, language?: MnemonicLanguage): void {
  if (!isValidMnemonic(mnemonic, language)) {
    // 秘密情報はメッセージに含めない。
    throw new VericertsError(ErrorCodes.INVALID_MNEMONIC);
  }
}

/**
 * 言語省略時に、ニーモニックが妥当な言語を総当りで特定する。
 *
 * `ALL_LANGUAGES` の順序で総当りし、最初に一致した言語を返す。
 * このため、ラテン文字を共有する言語（特に en と fr は約 100 語が共通）の間では
 * 判定が曖昧になり得る。共有語のみのニーモニックは参照順で先勝ちの言語に
 * 解決されるため、言語を一意に確定したい呼び出し側は `language` を明示すること。
 *
 * @returns 妥当な言語、見つからなければ `undefined`。
 */
function detectLanguage(mnemonic: string): MnemonicLanguage | undefined {
  return ALL_LANGUAGES.find((lang) => scureValidateMnemonic(mnemonic, WORDLISTS[lang]));
}

/**
 * ニーモニックの言語を解決する（明示指定があればそれを、省略時は `detectLanguage` で自動判定）。
 *
 * SLIP-0039 バックアップ（`shamir/index.ts`）が復元時に**同一言語**で BIP-39 ニーモニックを
 * 再構成するために言語を保持する必要があり、そのために本関数を公開する（BIP-39 のシードは
 * ニーモニック文字列そのものを PBKDF2 に渡すため、エントロピーが同じでも言語が違えば
 * 語が変わり、結果として別のシード＝別のウォレットになる）。
 *
 * 注意（自動判定の曖昧性）: `language` を省略すると `detectLanguage` による総当り判定を用いる。
 * 英語とフランス語は約 100 語を共有しており、共有語のみのニーモニックは参照順で先勝ちの言語に
 * 解決され得る。言語を確実に区別したい場合は `language` を明示すること。
 *
 * @param mnemonic 対象のニーモニック。
 * @param language 言語。省略時は自動判定（上記の曖昧性に注意）。
 * @returns 解決された言語。
 * @throws 語数不正・言語判定不能の場合（VericertsError、code `1001`）。
 */
export function resolveMnemonicLanguage(
  mnemonic: string,
  language?: MnemonicLanguage,
): MnemonicLanguage {
  if (!hasAllowedWordCount(mnemonic)) {
    throw new VericertsError(ErrorCodes.INVALID_MNEMONIC);
  }
  const resolved = language ?? detectLanguage(mnemonic);
  if (resolved === undefined) {
    throw new VericertsError(ErrorCodes.INVALID_MNEMONIC);
  }
  return resolved;
}

/**
 * ニーモニックを元のエントロピー（バイト列）へ復元する。
 *
 * @param mnemonic 変換対象のニーモニック。
 * @param language 言語。省略時は自動判定（`resolveMnemonicLanguage` 参照）。
 * @returns エントロピーのバイト列。
 * @throws 不正なニーモニックの場合（VericertsError、code `1001`）。
 */
export function mnemonicToEntropy(mnemonic: string, language?: MnemonicLanguage): Uint8Array {
  const resolved = resolveMnemonicLanguage(mnemonic, language);
  try {
    return scureMnemonicToEntropy(mnemonic, getWordlist(resolved));
  } catch {
    // @scure のチェックサム不正等を本 SDK のコードへ正規化する。
    // @scure 例外メッセージにエントロピー等の秘密が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.INVALID_MNEMONIC);
  }
}

/**
 * エントロピー（バイト列）から BIP-39 ニーモニックを生成する。
 *
 * @param entropy 16 バイト（128bit）または 32 バイト（256bit）のエントロピー。
 * @param language 言語。省略時は英語（`en`）。
 * @returns 空白区切りのニーモニック文字列。
 * @throws エントロピー長が不正な場合（VericertsError、code `1001`）。
 */
export function entropyToMnemonic(entropy: Uint8Array, language: MnemonicLanguage = 'en'): string {
  try {
    return scureEntropyToMnemonic(entropy, getWordlist(language));
  } catch {
    // @scure のエントロピー長不正等を本 SDK のコードへ正規化する。
    // @scure 例外メッセージにエントロピー等の秘密が含まれ得るため cause は渡さない。
    throw new VericertsError(ErrorCodes.INVALID_MNEMONIC);
  }
}
