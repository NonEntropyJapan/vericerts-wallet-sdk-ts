/**
 * 署名側の時刻入力（`nowSeconds` / `now` / `iatSeconds` / 寿命）の fail-closed 検証。
 *
 * NaN / ±Infinity / 負値 / 文字列を渡すと、JSON 直列化で `iat: null` や `iat: "5"` の JWT が署名され、
 * 検証側が必ず弾く（または鮮度判定が成立しない）トークンに署名鍵を使うことになる。
 * 署名前に VericertsError で拒否し、署名が一度も呼ばれないことも確認する。
 */

import { describe, expect, it } from 'bun:test';
import { isEpochSeconds, isLifetimeSeconds } from '../option-guard.js';
import { BAD_LIFETIMES, BAD_TIMES, NOW } from './signing-time.fixtures.js';

describe('isEpochSeconds / isLifetimeSeconds', () => {
  it('有限・非負・Date 範囲内のみ受理する', () => {
    expect(isEpochSeconds(0)).toBe(true);
    expect(isEpochSeconds(NOW)).toBe(true);
    for (const bad of [...BAD_TIMES, undefined, 1e12, 253_402_300_800]) {
      expect(isEpochSeconds(bad)).toBe(false);
    }
  });

  it('寿命は正の有限数で、起点との和が範囲内', () => {
    expect(isLifetimeSeconds(NOW, 300)).toBe(true);
    for (const bad of [...BAD_LIFETIMES, undefined, 1e12]) {
      expect(isLifetimeSeconds(NOW, bad)).toBe(false);
    }
  });
});
