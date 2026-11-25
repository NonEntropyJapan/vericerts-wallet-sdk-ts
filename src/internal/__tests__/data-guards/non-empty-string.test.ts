/**
 * 共有ユーティリティ `internal/prototype-safety/non-empty-string.ts` の判定規則を固定するテスト。
 *
 * 同等のヘルパが 10 ファイルに 10 件の名前付き定義として重複し、さらに 15 ファイルの 18 箇所が
 * 同等の判定をローカルに書いていたのを一本化した際の**挙動不変**を担保する。シグネチャは 5 種類
 * （`(value: unknown): value is string` 6 件 / `(value: string): boolean` 1 件 /
 * `(value: string | undefined): value is string` 1 件 / `(value: unknown): boolean` 1 件 /
 * `(value: unknown): string | undefined` 1 件）に分かれていた。意味論は 2 つ
 * （旧定義の内訳は `length` ベース 7 件 / `trim` ベース 3 件）で、統合先を取り違えると
 * 「空白のみの文字列」の扱いが箇所ごとに変わる。
 *
 * - `isNonEmptyString`: `length > 0`（空白のみは**通す**）
 * - `isNonBlankString`: `trim().length > 0`（空白のみは**弾く**。`String.prototype.trim` は
 *   U+00A0 / U+3000 も除去するため、非 ASCII 空白のみの文字列も弾く）
 */

import { describe, expect, it } from 'bun:test';
import {
  isNonBlankString,
  isNonEmptyString,
  toFiniteNumber,
} from '../../prototype-safety/non-empty-string.js';

/** 文字列以外の値（型の無い JS 呼び出し側から来得るもの）。 */
const NON_STRINGS: readonly unknown[] = [
  undefined,
  null,
  0,
  1,
  Number.NaN,
  true,
  false,
  {},
  [],
  ['a'],
  Symbol('a'),
  () => 'a',
  new String('a'),
];

/**
 * 非 ASCII 空白。`String.prototype.trim` は U+00A0（NBSP）と U+3000（全角スペース）も除去する。
 * リテラルでは目視できないためコードポイント escape で書く。
 */
const NBSP = '\u00a0';
const IDEOGRAPHIC_SPACE = '\u3000';

describe('isNonEmptyString', () => {
  it('非空文字列は true', () => {
    expect(isNonEmptyString('a')).toBe(true);
    expect(isNonEmptyString('https://verifier.example')).toBe(true);
  });

  it('空文字は false', () => {
    expect(isNonEmptyString('')).toBe(false);
  });

  it('空白のみの文字列は true（長さだけを見る規則）', () => {
    expect(isNonEmptyString(' ')).toBe(true);
    expect(isNonEmptyString('\t\n')).toBe(true);
  });

  it('文字列でない値はすべて false（型の無い呼び出し側からの入力も弾く）', () => {
    for (const value of NON_STRINGS) {
      expect(isNonEmptyString(value)).toBe(false);
    }
  });
});

describe('isNonBlankString', () => {
  it('非空白の文字列は true（前後に空白があっても中身があれば true）', () => {
    expect(isNonBlankString('a')).toBe(true);
    expect(isNonBlankString('  a  ')).toBe(true);
  });

  it('空文字・空白のみは false', () => {
    expect(isNonBlankString('')).toBe(false);
    expect(isNonBlankString(' ')).toBe(false);
    expect(isNonBlankString('\t\n ')).toBe(false);
  });

  it('文字列でない値はすべて false', () => {
    for (const value of NON_STRINGS) {
      expect(isNonBlankString(value)).toBe(false);
    }
  });

  it('isNonEmptyString より厳しい（isNonBlankString ⊆ isNonEmptyString）', () => {
    for (const value of [
      '',
      ' ',
      '\t',
      NBSP,
      IDEOGRAPHIC_SPACE,
      'a',
      '  a  ',
      `${IDEOGRAPHIC_SPACE}a${IDEOGRAPHIC_SPACE}`,
      ...NON_STRINGS,
    ]) {
      if (isNonBlankString(value)) {
        expect(isNonEmptyString(value)).toBe(true);
      }
    }
  });
});

/**
 * 非 ASCII 空白での挙動差を固定する。`isNonBlankString` の主用途は Credential Manifest の
 * 識別子・表示名で、日本語入力では全角スペースだけの値が現実的に入り得る。`trim` は NBSP /
 * 全角スペースも除去するため、これらのみの値は「有意な値ではない」として弾かれなければならない。
 */
describe('非 ASCII 空白（U+00A0 / U+3000）', () => {
  const BLANK_ONLY = [
    NBSP,
    IDEOGRAPHIC_SPACE,
    `${NBSP}${IDEOGRAPHIC_SPACE}`,
    `${IDEOGRAPHIC_SPACE} ${NBSP}\t\n`,
  ];

  it('非 ASCII 空白のみは isNonEmptyString で true（長さだけを見る規則）', () => {
    for (const value of BLANK_ONLY) {
      expect(isNonEmptyString(value)).toBe(true);
    }
  });

  it('非 ASCII 空白のみは isNonBlankString で false（trim が NBSP / 全角スペースも除去する）', () => {
    for (const value of BLANK_ONLY) {
      expect(isNonBlankString(value)).toBe(false);
    }
  });

  it('非 ASCII 空白に囲まれた中身は isNonBlankString でも true', () => {
    expect(isNonBlankString(`${IDEOGRAPHIC_SPACE}運転免許証${IDEOGRAPHIC_SPACE}`)).toBe(true);
    expect(isNonBlankString(`${NBSP}a${NBSP}`)).toBe(true);
  });
});

describe('toFiniteNumber', () => {
  it('有限数・数値文字列は number 化する', () => {
    expect(toFiniteNumber(60)).toBe(60);
    expect(toFiniteNumber('60')).toBe(60);
    expect(toFiniteNumber(0)).toBe(0);
  });

  it('NaN・Infinity・空白のみ・数値以外の文字列・非数値非文字列は null', () => {
    expect(toFiniteNumber(Number.NaN)).toBeNull();
    expect(toFiniteNumber(Number.POSITIVE_INFINITY)).toBeNull();
    expect(toFiniteNumber(' ')).toBeNull();
    expect(toFiniteNumber('soon')).toBeNull();
    for (const value of NON_STRINGS.filter((v) => typeof v !== 'number')) {
      expect(toFiniteNumber(value)).toBeNull();
    }
  });
});
