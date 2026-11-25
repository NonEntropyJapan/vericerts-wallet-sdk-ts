/**
 * `validKindHint` の単体回帰テスト。
 *
 * `options.kind` は `TrustedListKind`（`'lotl' | 'tsl' | 'auto'`）として型付けされているが、呼び
 * 出し側が型を無視した値を注入し得る。ユニオン外の値が自動判定（`auto`）へフォールバックすること、
 * ユニオン内の値がそのまま通ることを確認する。
 */

import { describe, expect, test } from 'bun:test';
import { validKindHint } from '../input/kind-hint.js';

describe('validKindHint', () => {
  test.each(['lotl', 'tsl', 'auto'] as const)('ユニオン内の値 %s はそのまま通す', (kind) => {
    expect(validKindHint(kind)).toBe(kind);
  });

  test('未指定は auto にフォールバックする', () => {
    expect(validKindHint(undefined)).toBe('auto');
  });

  test.each([
    ['空文字列', ''],
    ['誤字', 'tls'],
    ['大文字違い', 'TSL'],
    ['プロトタイプ汚染文字列', '__proto__'],
  ])('ユニオン外の値(%s)は auto にフォールバックする', (_label, kind) => {
    expect(validKindHint(kind as never)).toBe('auto');
  });
});
