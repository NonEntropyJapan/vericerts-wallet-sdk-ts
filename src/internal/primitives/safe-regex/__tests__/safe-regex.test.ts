/**
 * 線形時間正規表現エンジンの回帰テスト。
 *
 * - 意味論: ネイティブ `RegExp`（`u` フラグ）と真偽が一致すること（差分テスト）。
 * - 安全性: 静的検知を迂回していた 10 文字前後のパターンが、入力が長くても線形時間で終わること。
 * - 拒否: 後方参照・先読み等の線形時間で扱えない構文と構文不正を fail-closed に報告すること。
 */

import { describe, expect, it } from 'bun:test';
import { compileSafeRegex, SafeRegexError } from '../index.js';

const INPUTS = [
  '',
  'a',
  'ab',
  'abc',
  'aaaa',
  'aaaab',
  'abab',
  'ba',
  'Hello World',
  'did:web:example.com',
  '2026-10-03',
  'foo@bar.example',
  'x_y z',
  'ÄÖü 日本語',
  '😀a😀',
  'a\nb',
  '[]{}()|*+?',
];

const PATTERNS = [
  'a',
  '^a',
  'a$',
  '^a+$',
  '^(a|ab)*$',
  '^(ab|a)(bc|c)?$',
  'a*',
  '(?:ab)+',
  '^[a-z]+$',
  '^[^a-c]+$',
  '^\\d{4}-\\d{2}-\\d{2}$',
  '^did:[a-z0-9]+:[A-Za-z0-9._-]+$',
  '^[\\w.+-]+@[\\w-]+(\\.[\\w-]+)+$',
  '\\bWorld\\b',
  '\\Bor\\B',
  'a{2}',
  'a{2,}',
  'a{1,3}b?',
  '^(?:a|b){2,3}$',
  '^.$',
  '^.+$',
  '^\\p{L}+( \\p{L}+)*$',
  '^\\P{L}+$',
  '^[\\u3040-\\u30ff\\u4e00-\\u9fff]+$',
  '^\\u{1F600}',
  '^[*+?{}()|\\[\\]]+$',
  '^(?<year>\\d{4})-(\\d{2})$',
  'a|',
  '()',
  '(?:)*',
  '^(?:a?){3}a{3}$',
  '^(a*)*$',
  'a+?b',
  '^\\x61\\u0062\\cJ?',
  '\\/',
  '^$',
];

describe('compileSafeRegex — ネイティブ RegExp（u フラグ）と真偽が一致する', () => {
  for (const pattern of PATTERNS) {
    it(`/${pattern}/u`, () => {
      const safe = compileSafeRegex(pattern);
      const native = new RegExp(pattern, 'u');
      for (const input of INPUTS) {
        expect(safe.test(input)).toBe(native.test(input));
      }
    });
  }
});

describe('compileSafeRegex — ReDoS パターンが線形時間で終わる', () => {
  // 旧静的検知（hasCatastrophicBacktracking）を素通りし、ネイティブでは分〜指数時間かかる形。
  const attacks: Array<[string, string]> = [
    ['^(a*){10}b', `${'a'.repeat(5_000)}`],
    ['^(?:a+){10}$', `${'a'.repeat(5_000)}!`],
    ['^(a+){30}$', `${'a'.repeat(5_000)}!`],
    ['^(?:a?){28}a{28}$', 'a'.repeat(27)],
    ['^(a+)+$', `${'a'.repeat(5_000)}!`],
    ['^(.|.)*x$', `${'a'.repeat(5_000)}`],
    ['(a|a)*b', 'a'.repeat(5_000)],
    [`${'a+'.repeat(20)}b`, 'a'.repeat(1_000)],
  ];
  for (const [pattern, input] of attacks) {
    it(`/${pattern}/ は 1 秒未満で結果を返す`, () => {
      const safe = compileSafeRegex(pattern);
      const startedAt = performance.now();
      let result: boolean | 'too-complex';
      try {
        result = safe.test(input);
      } catch (error) {
        // 入力が大きく予算を使い切る場合も、固まらずに中断できればよい。
        expect(error).toBeInstanceOf(SafeRegexError);
        result = 'too-complex';
      }
      expect(performance.now() - startedAt).toBeLessThan(1_000);
      expect(result === false || result === 'too-complex').toBe(true);
    });
  }

  it('11 文字の攻撃パターン ^(a*){10}b は 40 文字入力で即座に不一致を返す', () => {
    const startedAt = performance.now();
    expect(compileSafeRegex('^(a*){10}b').test('a'.repeat(40))).toBe(false);
    expect(performance.now() - startedAt).toBeLessThan(200);
  });
});

describe('compileSafeRegex — 予算と上限', () => {
  it('共有予算を使い切ると too-complex を投げ、以降も投げ続ける', () => {
    const safe = compileSafeRegex('^[a-z]+$');
    const budget = { remaining: 50 };
    expect(() => safe.test('a'.repeat(40), budget)).toThrow(SafeRegexError);
    expect(() => safe.test('a', budget)).toThrow(SafeRegexError);
  });

  it('パターン長 512 超・展開サイズ超過は too-complex', () => {
    for (const source of ['a'.repeat(513), '((a{1000}){1000}){1000}', '(?:a{1000}){5}']) {
      expect(() => compileSafeRegex(source)).toThrow(
        expect.objectContaining({ reason: 'too-complex' }),
      );
    }
  });

  it('群のネストが深すぎるパターンは too-complex', () => {
    expect(() => compileSafeRegex(`${'('.repeat(40)}a${')'.repeat(40)}`)).toThrow(
      expect.objectContaining({ reason: 'too-complex' }),
    );
  });
});

describe('compileSafeRegex — fail-closed の拒否', () => {
  it.each([
    '(a)\\1',
    '(?<n>a)\\k<n>',
    '(?=a)',
    '(?!a)',
    '(?<=a)b',
    '(?<!a)b',
    '(?i:a)',
  ])('%s は unsupported', (source) => {
    expect(() => compileSafeRegex(source)).toThrow(
      expect.objectContaining({ reason: 'unsupported' }),
    );
  });

  it.each([
    '(',
    'a)',
    '[a',
    '*a',
    'a**',
    '^*',
    '\\b+',
    'a{2,1}',
    'a{',
    '{',
    '}',
    ']',
    '\\',
    '\\q',
  ])('%s は syntax', (source) => {
    expect(() => compileSafeRegex(source)).toThrow(expect.objectContaining({ reason: 'syntax' }));
  });
});
