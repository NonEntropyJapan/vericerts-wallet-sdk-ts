/**
 * 正規表現パーサの原子レベルの補助（ネイティブ `RegExp` への委譲・エスケープ長・量化子の先読み）。
 *
 * 公開 API からは直接呼ばれない内部実装。
 * `parse.ts` から分離してファイルサイズを抑える。
 *
 * `unicode`（`u` フラグ）の有無で構文が分かれる。`u` なしは ECMA-262 Annex B の寛容構文
 * （`\:` のような恒等エスケープ・`[\w-.]`・リテラルの `{`）を受理し、入力を UTF-16 コード
 * ユニット単位で扱う（ネイティブの非 `u` RegExp と同じ）。
 */

import { SafeRegexError } from './error.js';
import type { RegexNode } from './parse.js';

/** 1 原子だけをネイティブ `RegExp` へ委譲した述語にする。構文不正は `syntax`。 */
export function nativeAtom(source: string, unicode: boolean): RegexNode {
  let re: RegExp;
  try {
    re = new RegExp(`^(?:${source})$`, unicode ? 'u' : '');
  } catch {
    throw new SafeRegexError('syntax');
  }
  return { t: 'atom', test: (cp) => re.test(String.fromCodePoint(cp)) };
}

export const isDigit = (ch: string | undefined): boolean =>
  ch !== undefined && ch >= '0' && ch <= '9';
const isHex = (ch: string | undefined): boolean => ch !== undefined && /^[0-9A-Fa-f]$/.test(ch);
const isAsciiLetter = (ch: string | undefined): boolean =>
  ch !== undefined && /^[A-Za-z]$/.test(ch);

/** `pos` が `{n}` / `{n,}` / `{n,m}` の構文で始まるか（`u` なしでは、そうでない `{` はリテラル）。 */
export function bracedQuantifierAhead(src: readonly string[], pos: number): boolean {
  let i = pos + 1;
  const digitsFrom = i;
  while (isDigit(src[i])) {
    i += 1;
  }
  if (i === digitsFrom) {
    return false;
  }
  if (src[i] === ',') {
    i += 1;
    while (isDigit(src[i])) {
      i += 1;
    }
  }
  return src[i] === '}';
}

/**
 * `\` から始まるエスケープ全体の長さ（`\` を含む。`src[pos]` が `\`、`kind` が次の文字）。
 *
 * @throws SafeRegexError `syntax`（`u` モードでの不正なエスケープ）/ `unsupported`（`u` なしの
 *   レガシー 8 進・`\c` + 非英字。線形時間エンジンでは意味論を再現しない）。
 */
export function escapeLength(
  src: readonly string[],
  pos: number,
  kind: string,
  unicode: boolean,
): number {
  if (unicode && (kind === 'p' || kind === 'P' || (kind === 'u' && src[pos + 2] === '{'))) {
    let end = pos + 2;
    while (src[end] !== '}') {
      if (end >= src.length) {
        throw new SafeRegexError('syntax');
      }
      end += 1;
    }
    return end + 1 - pos;
  }
  if (kind === 'u' || kind === 'x') {
    const digits = kind === 'u' ? 4 : 2;
    for (let k = 0; k < digits; k += 1) {
      if (!isHex(src[pos + 2 + k])) {
        if (unicode) {
          throw new SafeRegexError('syntax');
        }
        return 2; // Annex B: 16 進が揃わない `\u` / `\x` は恒等エスケープ。
      }
    }
    return 2 + digits;
  }
  if (kind === '0' && isDigit(src[pos + 2])) {
    throw new SafeRegexError(unicode ? 'syntax' : 'unsupported');
  }
  if (kind === 'c') {
    if (!unicode && !isAsciiLetter(src[pos + 2])) {
      throw new SafeRegexError('unsupported');
    }
    return 3;
  }
  return 2;
}
