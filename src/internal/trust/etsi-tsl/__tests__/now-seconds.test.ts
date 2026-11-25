/**
 * `resolveNowSeconds` の受理側境界に対する単体回帰テスト。
 *
 * `now-seconds-guard.test.ts` は拒否側（`8_640_000_000_001`、`-1` など）を `loadTrustedList` 経由の
 * e2e で検証しているが、受理側の境界（ちょうど `0` と `MAX_EPOCH_SECONDS`）は未検証だった。その
 * ため、境界判定を `<=` から `<` に、`>= 0` から `> 0` に書き換えても既存テストは全て通ってしまう
 * 状態だった。`resolveNowSeconds` を直接呼び、境界値がそのまま採用される（実時計へフォールバック
 * しない）ことを確認する。
 */

import { describe, expect, test } from 'bun:test';
import { resolveNowSeconds } from '../input/now-seconds.js';

const MAX_EPOCH_SECONDS = 8_640_000_000_000;

describe('resolveNowSeconds', () => {
  test('下限の境界値 0 をそのまま採用する', () => {
    expect(resolveNowSeconds({ nowSeconds: 0 })).toBe(0);
  });

  test('上限の境界値 MAX_EPOCH_SECONDS をそのまま採用する', () => {
    expect(resolveNowSeconds({ nowSeconds: MAX_EPOCH_SECONDS })).toBe(MAX_EPOCH_SECONDS);
  });
});
