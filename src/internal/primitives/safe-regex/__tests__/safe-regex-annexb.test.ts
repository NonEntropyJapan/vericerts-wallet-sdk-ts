/**
 * `compileSafeRegex(source, { unicode: false })`（`u` なし = ECMA-262 Annex B 互換）の回帰テスト。
 *
 * - 意味論: ネイティブの非 `u` `RegExp` と真偽が一致すること（差分テスト）。PEx `filter.pattern` は
 *   従来 `new RegExp(pattern)` で評価されていたため、`\:` / `[\w-.]` / リテラルの `{` が通ること。
 * - 安全性: 非 `u` モードでも後方参照・先読みは拒否し、線形時間であること。
 * - 互換を取らない構文は黙って別の意味にせず `unsupported` で明確に拒否すること。
 */

import { describe, expect, it } from 'bun:test';
import { compileSafeRegex, SafeRegexError } from '../index.js';

const INPUTS = [
  '',
  'a',
  'did:web:example.com',
  'did-web',
  'a.b@example.com',
  'a-b@example.com',
  'a_b@example.com',
  '123-4567',
  '123456',
  'a{',
  'a{1',
  '{}',
  '{abc}',
  'a}',
  'x]',
  'a@x',
  'axx',
  'u',
  'p{L}',
  'xA',
  'A',
  '😀',
  '😀😀',
  '\ud83d',
  'a\nb',
];

const PATTERNS = [
  '^did\\:web\\:example\\.com$',
  '^[\\w-.]+@example\\.com$',
  '^[\\w-.]+$',
  '^[.-\\w]+$',
  '^\\d{3}\\-\\d{4}$',
  '^a{$',
  'a{1',
  '^{abc}$',
  '{}',
  'a{,5}',
  'a}',
  'x]',
  '^[a-z]+\\@x$',
  '^\\x$',
  '^\\u$',
  '^\\p{L}$',
  '^\\u{4}$',
  '^u{4}$',
  '^\\ud83d\\ude00$',
  '^.$',
  '^..$',
  '^[😀]$',
  '^😀+$',
  'a{2}',
  '^(?:a|b){0,3}$',
  '^[^]$',
  '[]',
  '\\-',
];

describe('compileSafeRegex({ unicode: false }) — 非 u の RegExp と真偽が一致する', () => {
  for (const pattern of PATTERNS) {
    it(`/${pattern}/`, () => {
      const safe = compileSafeRegex(pattern, { unicode: false });
      const native = new RegExp(pattern);
      for (const input of INPUTS) {
        expect(safe.test(input)).toBe(native.test(input));
      }
    });
  }
});

describe('compileSafeRegex({ unicode: false }) — u モードでは拒否される Annex B 構文を受理する', () => {
  it.each([
    ['^did\\:web\\:example\\.com$', 'did:web:example.com'],
    ['^[\\w-.]+@example\\.com$', 'a.b@example.com'],
    ['^\\d{3}\\-\\d{4}$', '123-4567'],
    ['^a{$', 'a{'],
    ['^[a-z]+\\@x$', 'a@x'],
  ])('%s は %s に一致する（既定の u モードでは syntax）', (source, input) => {
    expect(compileSafeRegex(source, { unicode: false }).test(input)).toBe(true);
    expect(() => compileSafeRegex(source)).toThrow(expect.objectContaining({ reason: 'syntax' }));
  });
});

describe('compileSafeRegex({ unicode: false }) — 安全性は u モードと同じ', () => {
  it.each([
    '(a)\\1',
    '(?<n>a)\\k<n>',
    '\\k',
    '(?=a)',
    '(?!a)',
    '(?<=a)b',
    '(?i:a)',
    '\\00',
    '\\cé',
  ])('%s は unsupported', (source) => {
    expect(() => compileSafeRegex(source, { unicode: false })).toThrow(
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
    '{2}',
    '^{2}',
    'a{2}{3}',
    '\\',
  ])('%s は syntax', (source) => {
    expect(() => compileSafeRegex(source, { unicode: false })).toThrow(
      expect.objectContaining({ reason: 'syntax' }),
    );
  });

  it('展開サイズの上限は変わらない', () => {
    expect(() => compileSafeRegex('((a{1000}){1000}){1000}', { unicode: false })).toThrow(
      expect.objectContaining({ reason: 'too-complex' }),
    );
  });

  it('^(a*){10}b は長い入力でも線形時間で不一致を返す', () => {
    const safe = compileSafeRegex('^(a*){10}b', { unicode: false });
    const startedAt = performance.now();
    expect(safe.test('a'.repeat(1_000))).toBe(false);
    expect(performance.now() - startedAt).toBeLessThan(1_000);
  });

  it('予算を使い切ると too-complex を投げる', () => {
    const safe = compileSafeRegex('^[a-z]+$', { unicode: false });
    expect(() => safe.test('a'.repeat(40), { remaining: 50 })).toThrow(SafeRegexError);
  });
});
