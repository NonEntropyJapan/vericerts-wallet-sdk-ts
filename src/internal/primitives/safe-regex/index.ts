/**
 * 線形時間で評価する正規表現エンジン（ReDoS 防御）。
 *
 * JSON Schema の `pattern` / `patternProperties` と Presentation Exchange の `filter.pattern` から使う
 * 内部実装。公開バレルからは re-export しない。
 *
 * **なぜ静的検知ではなくエンジンなのか**: `pattern` も検証対象の値も外部由来（Issuer / Verifier）で、
 * ネイティブ `RegExp` はマッチ実行中に中断できない。「危険な形を検知して拒否する」方式は
 * `(a*){10}b` や `(?:a?){28}a{28}` のように検知の隙間を突く 10 文字前後のパターンで破られ続ける
 * そのため外部由来のパターンはネイティブ `RegExp` に渡さず、バックトラッキングを
 * しない NFA 同時進行で評価する。時間は O(命令数 × 入力長) で、ステップ予算（{@link RegexBudget}）に
 * 達したら `too-complex` で中断できる。
 *
 * **サブセット**: 選択・連接・群（キャプチャ / 非キャプチャ / 名前付き）・量化子・`^` `$` `\b` `\B`・
 * 文字クラス・`\d` `\w` `\s` `\p{..}` 等。後方参照・先読み・後読み・修飾子付き群は `unsupported`。
 * 意味論は既定で `u` フラグ付き `RegExp#test` と一致する（真偽判定のため貪欲 / 非貪欲は無関係）。
 * `unicode: false` は `u` なしの `RegExp#test`（ECMA-262 Annex B の寛容構文・UTF-16 コードユニット単位）
 * と一致する。Annex B のうち意味論を再現しない構文（`\k` / 後方参照 / レガシー 8 進 / `\c` + 非英字）は
 * `unsupported` で拒否する。いずれのモードでも後方参照・先読みは扱わないため安全性は変わらない。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import { SafeRegexError } from './error.js';
import { parseRegex } from './parse.js';
import { compileProgram, DEFAULT_REGEX_STEPS, type RegexBudget, runProgram } from './program.js';

export { SafeRegexError, type SafeRegexFailure } from './error.js';
export { DEFAULT_REGEX_STEPS, type RegexBudget } from './program.js';

/** 受理するパターン長の上限（文字数）。 */
export const MAX_PATTERN_LENGTH = 512;

/** コンパイル済みの線形時間正規表現。 */
export interface SafeRegex {
  /**
   * `value` のどこかにパターンが一致するか（`RegExp#test` 相当）。
   *
   * @param budget 共有する評価ステップ予算。省略時は {@link DEFAULT_REGEX_STEPS} を 1 回分使う。
   * @throws SafeRegexError `too-complex` — 予算を使い切った。
   */
  test(value: string, budget?: RegexBudget): boolean;
}

/** {@link compileSafeRegex} のオプション。 */
export interface CompileOptions {
  /**
   * `u` フラグ相当で解釈するか（既定 `true`）。`false` は `u` なしの RegExp と同じ Annex B 互換
   * （`\:` `[\w-.]` リテラルの `{` を受理し、UTF-16 コードユニット単位で照合する）。
   */
  readonly unicode?: boolean;
}

/**
 * パターンをコンパイルする。
 *
 * @throws SafeRegexError `syntax`（構文不正）/ `unsupported`（線形時間で扱えない構文）/
 *   `too-complex`（長さ・展開サイズの超過）。
 */
export function compileSafeRegex(source: string, options: CompileOptions = {}): SafeRegex {
  if (source.length > MAX_PATTERN_LENGTH) {
    throw new SafeRegexError('too-complex');
  }
  const unicode = ownProperty<boolean>(options, 'unicode') ?? true;
  const program = compileProgram(parseRegex(source, unicode));
  return {
    test: (value, budget) =>
      runProgram(program, value, budget ?? { remaining: DEFAULT_REGEX_STEPS }, unicode),
  };
}
