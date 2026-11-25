/**
 * 末尾スラッシュ除去（`internal/trim-trailing-slashes.ts`）の回帰テスト。
 *
 * 旧実装 `replace(/\/+$/, '')` は `/` の長い連続の後ろに別の文字が続く入力で O(n²) になり、
 * Offer の `credential_issuer` / VC の `iss` だけで数秒〜数分ハングした。時間の上限は旧実装が
 * 十数秒かかる入力に対する十分に緩い値で、通常の CI ゆらぎでは誤検知しない。
 */

import { describe, expect, test } from 'bun:test';
import { sameIdentifier } from '../../auth/oid4vci/identifier/same-identifier.js';
import { trimTrailingSlashes } from '../trim-trailing-slashes.js';

const HUGE = 200_000;
const BUDGET_MS = 1_000;

function elapsedMs(run: () => void): number {
  const start = performance.now();
  run();
  return performance.now() - start;
}

describe('trimTrailingSlashes', () => {
  test.each([
    ['https://as.example', 'https://as.example'],
    ['https://as.example/', 'https://as.example'],
    ['https://as.example///', 'https://as.example'],
    ['https://as.example/a/b/', 'https://as.example/a/b'],
    ['/', ''],
    ['////', ''],
    ['', ''],
    ['a//b', 'a//b'],
  ])('%j → %j', (input, expected) => {
    expect(trimTrailingSlashes(input)).toBe(expected);
  });

  test('`/` の長い連続の後ろに文字が続く入力でも線形時間で終わる', () => {
    const value = `https://issuer.example.com/${'/'.repeat(HUGE)}x`;
    let trimmed = '';
    expect(elapsedMs(() => (trimmed = trimTrailingSlashes(value)))).toBeLessThan(BUDGET_MS);
    expect(trimmed).toBe(value);
  });

  test('`/` だけの巨大入力は全部除く', () => {
    expect(trimTrailingSlashes('/'.repeat(HUGE))).toBe('');
  });
});

describe('sameIdentifier', () => {
  test('末尾スラッシュの有無だけの差は同一、それ以外は別', () => {
    expect(sameIdentifier('https://as.example/', 'https://as.example')).toBe(true);
    expect(sameIdentifier('https://as.example//', 'https://as.example/')).toBe(true);
    expect(sameIdentifier('https://as.example/a', 'https://as.example')).toBe(false);
  });

  test('攻撃者が長さを決める識別子でも線形時間で比較を終える', () => {
    const hostile = `https://issuer.example.com/${'/'.repeat(HUGE)}x`;
    let same = true;
    expect(
      elapsedMs(() => (same = sameIdentifier(hostile, 'https://issuer.example.com'))),
    ).toBeLessThan(BUDGET_MS);
    expect(same).toBe(false);
  });
});
