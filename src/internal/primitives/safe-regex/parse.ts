/**
 * 正規表現ソース（既定は `u` フラグ相当、`unicode: false` で Annex B 互換）の構造パーサ。AST を返す。
 *
 * 公開 API からは直接呼ばれない内部実装。
 *
 * 構造（選択・連接・群・量化子・`^` `$` `\b` `\B`）だけを自前で解釈し、**1 文字に一致する原子**
 * （リテラル・`.`・`\d` `\w` `\s` `\p{..}` 等のエスケープ・`[...]` 文字クラス）は、その原子 1 つだけを
 * ネイティブ `RegExp`（`^(?:原子)$`、`u` フラグ）にコンパイルした述語へ委譲する。量化子を含まない
 * 単一原子のマッチは線形時間なので、Unicode プロパティ等の意味論をネイティブと一致させつつ、
 * バックトラッキングの経路を持ち込まない。
 *
 * 線形時間で評価できない構文（後方参照 `\1` / `\k<n>`、先読み・後読み、修飾子付き群 `(?i:`）は
 * `unsupported` で拒否する。真偽のみを問う `test` では貪欲 / 非貪欲の違いは結果に影響しない。
 */

import { bracedQuantifierAhead, escapeLength, isDigit, nativeAtom } from './atoms.js';
import { SafeRegexError } from './error.js';

/** アサーションの種別。 */
export type AssertionKind = 'bol' | 'eol' | 'wordBoundary' | 'notWordBoundary';

/** 正規表現 AST。 */
export type RegexNode =
  | { readonly t: 'atom'; readonly test: (codePoint: number) => boolean }
  | { readonly t: 'assert'; readonly kind: AssertionKind }
  | { readonly t: 'cat'; readonly items: readonly RegexNode[] }
  | { readonly t: 'alt'; readonly items: readonly RegexNode[] }
  | { readonly t: 'rep'; readonly node: RegexNode; readonly min: number; readonly max: number };

/** 1 つの量化子で許す繰り返し回数の上限（NFA 展開サイズの暴走を防ぐ）。 */
const MAX_REPEAT = 1000;
/** 群のネスト上限（再帰パーサのスタック枯渇防止）。 */
const MAX_GROUP_DEPTH = 32;

/** パース状態。入力はコードポイント単位の配列。 */
class Parser {
  private pos = 0;

  /**
   * @param src 入力（`unicode` ならコードポイント、でなければ UTF-16 コードユニットの配列）。
   * @param unicode `u` フラグ相当か。`false` は ECMA-262 Annex B の寛容構文。
   */
  constructor(
    private readonly src: readonly string[],
    private readonly unicode: boolean,
  ) {}

  /** パターン全体をパースする。 */
  parseAll(): RegexNode {
    const node = this.parseAlt(0);
    if (this.pos < this.src.length) {
      // 対応する `(` の無い `)`。
      throw new SafeRegexError('syntax');
    }
    return node;
  }

  private peek(offset = 0): string | undefined {
    return this.src[this.pos + offset];
  }

  private parseAlt(depth: number): RegexNode {
    const items = [this.parseCat(depth)];
    while (this.peek() === '|') {
      this.pos += 1;
      items.push(this.parseCat(depth));
    }
    return items.length === 1 ? (items[0] as RegexNode) : { t: 'alt', items };
  }

  private parseCat(depth: number): RegexNode {
    const items: RegexNode[] = [];
    for (let ch = this.peek(); ch !== undefined && ch !== '|' && ch !== ')'; ch = this.peek()) {
      items.push(this.parseTerm(depth));
    }
    return { t: 'cat', items };
  }

  /** 原子（または群・アサーション）を 1 つ読み、後続の量化子を適用する。 */
  private parseTerm(depth: number): RegexNode {
    const ch = this.peek() as string;
    if (ch === '^' || ch === '$') {
      this.pos += 1;
      this.rejectQuantifier();
      return { t: 'assert', kind: ch === '^' ? 'bol' : 'eol' };
    }
    if (ch === '\\' && (this.peek(1) === 'b' || this.peek(1) === 'B')) {
      const kind = this.peek(1) === 'b' ? 'wordBoundary' : 'notWordBoundary';
      this.pos += 2;
      this.rejectQuantifier();
      return { t: 'assert', kind };
    }
    return this.parseQuantifier(this.parseAtom(depth));
  }

  /** アサーションへの量化子・量化子への量化子は構文エラー（`u` なしのリテラル `{` は除く）。 */
  private rejectQuantifier(): void {
    const next = this.peek();
    if (next === '*' || next === '+' || next === '?' || this.braceQuantifierStarts()) {
      throw new SafeRegexError('syntax');
    }
  }

  /** 現在位置の `{` が量化子として扱われるか（`u` モードでは `{` は常に量化子の開始）。 */
  private braceQuantifierStarts(): boolean {
    return this.peek() === '{' && (this.unicode || bracedQuantifierAhead(this.src, this.pos));
  }

  private literal(ch: string): RegexNode {
    this.pos += 1;
    const cp = ch.codePointAt(0) as number;
    return { t: 'atom', test: (c) => c === cp };
  }

  private parseAtom(depth: number): RegexNode {
    const ch = this.peek() as string;
    switch (ch) {
      case '(':
        return this.parseGroup(depth);
      case '.':
        this.pos += 1;
        return nativeAtom('.', this.unicode);
      case '[':
        return this.parseClass();
      case '\\':
        return this.parseEscape();
      case '*':
      case '+':
      case '?':
        // 繰り返す対象が無い量化子。
        throw new SafeRegexError('syntax');
      case '{':
        // `u` モードの単独の `{` / 繰り返す対象が無い `{n}` は構文エラー。Annex B は `a{` 等をリテラル扱い。
        if (this.braceQuantifierStarts()) {
          throw new SafeRegexError('syntax');
        }
        return this.literal(ch);
      case '}':
      case ']':
        if (this.unicode) {
          throw new SafeRegexError('syntax');
        }
        return this.literal(ch);
      default:
        return this.literal(ch);
    }
  }

  private parseGroup(depth: number): RegexNode {
    if (depth >= MAX_GROUP_DEPTH) {
      throw new SafeRegexError('too-complex');
    }
    this.pos += 1; // '('
    if (this.peek() === '?') {
      const marker = this.peek(1);
      if (marker === ':') {
        this.pos += 2;
      } else if (marker === '<' && this.peek(2) !== '=' && this.peek(2) !== '!') {
        // 名前付きキャプチャ群。名前の妥当性はキャプチャを使わないため検査しない。
        this.pos += 2;
        while (this.peek() !== '>') {
          if (this.peek() === undefined) {
            throw new SafeRegexError('syntax');
          }
          this.pos += 1;
        }
        this.pos += 1;
      } else {
        // 先読み `(?=` `(?!`・後読み `(?<=` `(?<!`・修飾子 `(?i:` は線形時間で扱えない。
        throw new SafeRegexError('unsupported');
      }
    }
    const inner = this.parseAlt(depth + 1);
    if (this.peek() !== ')') {
      throw new SafeRegexError('syntax');
    }
    this.pos += 1;
    return inner;
  }

  private parseClass(): RegexNode {
    const start = this.pos;
    let i = start + 1;
    while (i < this.src.length && this.src[i] !== ']') {
      i += this.src[i] === '\\' ? 2 : 1;
    }
    if (i >= this.src.length) {
      throw new SafeRegexError('syntax');
    }
    this.pos = i + 1;
    return nativeAtom(this.src.slice(start, i + 1).join(''), this.unicode);
  }

  private parseEscape(): RegexNode {
    const kind = this.peek(1);
    if (kind === undefined) {
      throw new SafeRegexError('syntax');
    }
    if (kind === 'k' || (isDigit(kind) && kind !== '0')) {
      // 後方参照は線形時間で扱えない。
      throw new SafeRegexError('unsupported');
    }
    const length = escapeLength(this.src, this.pos, kind, this.unicode);
    const text = this.src.slice(this.pos, this.pos + length).join('');
    this.pos += length;
    if (this.unicode && /^\\u[dD][89abAB]/.test(text)) {
      // 下位サロゲートの `\u` エスケープと対で 1 コードポイントになる形は単独では評価できない。
      throw new SafeRegexError('unsupported');
    }
    return nativeAtom(text, this.unicode);
  }

  /** 原子に続く量化子（`*` `+` `?` `{n}` `{n,}` `{n,m}`、末尾の `?` は非貪欲指定として読み捨てる）。 */
  private parseQuantifier(node: RegexNode): RegexNode {
    const ch = this.peek();
    let min: number;
    let max: number;
    if (ch === '*') {
      [min, max] = [0, Number.POSITIVE_INFINITY];
      this.pos += 1;
    } else if (ch === '+') {
      [min, max] = [1, Number.POSITIVE_INFINITY];
      this.pos += 1;
    } else if (ch === '?') {
      [min, max] = [0, 1];
      this.pos += 1;
    } else if (this.braceQuantifierStarts()) {
      [min, max] = this.parseBraceBounds();
    } else {
      return node;
    }
    if (this.peek() === '?') {
      this.pos += 1;
    }
    this.rejectQuantifier();
    return { t: 'rep', node, min, max };
  }

  private readNumber(): number | undefined {
    const from = this.pos;
    while (isDigit(this.peek())) {
      this.pos += 1;
    }
    if (this.pos === from) {
      return undefined;
    }
    const value = Number(this.src.slice(from, this.pos).join(''));
    if (value > MAX_REPEAT) {
      throw new SafeRegexError('too-complex');
    }
    return value;
  }

  /** `{n}` / `{n,}` / `{n,m}` を読む。`u` モードでは量化子として不正な `{` は構文エラー。 */
  private parseBraceBounds(): [number, number] {
    this.pos += 1; // '{'
    const min = this.readNumber();
    if (min === undefined) {
      throw new SafeRegexError('syntax');
    }
    let max = min;
    if (this.peek() === ',') {
      this.pos += 1;
      max = this.readNumber() ?? Number.POSITIVE_INFINITY;
    }
    if (this.peek() !== '}' || min > max) {
      throw new SafeRegexError('syntax');
    }
    this.pos += 1;
    return [min, max];
  }
}

/**
 * 正規表現ソースを AST にする。
 *
 * @param unicode `true`（既定）は `u` フラグ相当（コードポイント単位）。`false` は `u` なしの
 *   ネイティブ RegExp と同じ Annex B 互換（UTF-16 コードユニット単位）。
 */
export function parseRegex(source: string, unicode = true): RegexNode {
  return new Parser(unicode ? Array.from(source) : source.split(''), unicode).parseAll();
}
