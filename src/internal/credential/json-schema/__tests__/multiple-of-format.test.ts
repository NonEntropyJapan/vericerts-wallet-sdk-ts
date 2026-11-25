/**
 * `multipleOf`と `format: date` / `date-time` の暦検証の回帰テスト。
 */

import { describe, expect, it } from 'bun:test';
import { isMultipleOf } from '../multiple-of.js';
import { validateAgainstSchema } from '../validate.js';

const valid = (schema: Record<string, unknown>, value: unknown): boolean =>
  validateAgainstSchema(schema, value).valid;

describe('multipleOf は 10 進で厳密に判定する', () => {
  it('0.01 刻みの正当な値（0.28 / 0.29 / 19.99 / 4.35）を受理する', () => {
    for (const v of [0.28, 0.29, 19.99, 4.35, 0.47, 0.56, 0, -0.28]) {
      expect(valid({ multipleOf: 0.01 }, v)).toBe(true);
    }
  });

  it('0..99999 セントの総当たりで 0.01 の倍数はすべて valid', () => {
    const rejected: number[] = [];
    for (let cents = 0; cents < 100_000; cents++) {
      const amount = Number((cents / 100).toFixed(2));
      if (!isMultipleOf(amount, 0.01)) {
        rejected.push(amount);
      }
    }
    expect(rejected).toEqual([]);
  });

  it('0.01 の倍数でない値（0.285 / 0.2800001）を拒否する', () => {
    expect(valid({ multipleOf: 0.01 }, 0.285)).toBe(false);
    expect(valid({ multipleOf: 0.01 }, 0.2800001)).toBe(false);
  });

  it('multipleOf: 0.1 に 100.3 を受理し、既存の 0.3 も受理する', () => {
    expect(valid({ multipleOf: 0.1 }, 100.3)).toBe(true);
    expect(valid({ multipleOf: 0.1 }, 0.3)).toBe(true);
    expect(valid({ multipleOf: 0.1 }, 0.35)).toBe(false);
  });

  it('巨大値・微小差の非倍数を誤受理しない', () => {
    expect(valid({ multipleOf: 1 }, 5.000000000000001)).toBe(false);
    expect(valid({ multipleOf: 3 }, 1e20)).toBe(false);
    expect(valid({ multipleOf: 2 }, 1e20)).toBe(true);
    expect(valid({ multipleOf: 1e-7 }, 3e-7)).toBe(true);
    expect(valid({ multipleOf: 1e-7 }, 3.5e-7)).toBe(false);
  });

  it('整数の倍数判定は従来どおり', () => {
    expect(valid({ multipleOf: 2 }, 4)).toBe(true);
    expect(valid({ multipleOf: 2 }, 3)).toBe(false);
    expect(valid({ multipleOf: 2 }, -6)).toBe(true);
  });

  it('非有限値は倍数と認めない（fail-closed）', () => {
    expect(isMultipleOf(Number.NaN, 1)).toBe(false);
    expect(isMultipleOf(Number.POSITIVE_INFINITY, 1)).toBe(false);
    expect(isMultipleOf(1, Number.POSITIVE_INFINITY)).toBe(false);
  });
});

describe('format: date / date-time は暦として妥当な値のみ受理する', () => {
  it.each([
    '2025-13-45',
    '2024-02-30',
    '0000-00-00',
    '9999-99-99',
    '2025-04-31',
    '2023-02-29',
  ])('date: %s は invalid', (value) => {
    expect(valid({ format: 'date' }, value)).toBe(false);
  });

  it.each([
    '2025-13-45T99:99:99Z',
    '2025-02-30T00:00:00Z',
    '2025-12-01T24:00:00Z',
    '2024-12-01T25:61:61Z',
    '2025-12-01T00:00:00+99:99',
    '2025-12-01T00:00:00+24:00',
  ])('date-time: %s は invalid', (value) => {
    expect(valid({ format: 'date-time' }, value)).toBe(false);
  });

  it('閏日・境界・小数秒・小文字 t/z・オフセットは valid', () => {
    expect(valid({ format: 'date' }, '2024-02-29')).toBe(true);
    expect(valid({ format: 'date-time' }, '2024-02-29T23:59:59Z')).toBe(true);
    expect(valid({ format: 'date-time' }, '2025-12-01T00:00:00.123+09:00')).toBe(true);
    expect(valid({ format: 'date-time' }, '2025-12-01t00:00:00z')).toBe(true);
  });

  it('形式違い（桁数・区切り）は従来どおり invalid', () => {
    expect(valid({ format: 'date' }, '27/08/2026')).toBe(false);
    expect(valid({ format: 'date-time' }, '2026-08-27')).toBe(false);
    expect(valid({ format: 'date-time' }, '2026-08-27T00:00:00')).toBe(false);
  });

  it('継承プロパティ名の format（constructor 等）は未知として無視する', () => {
    expect(valid({ format: 'constructor' }, 'x')).toBe(true);
    expect(valid({ format: '__proto__' }, 'x')).toBe(true);
  });
});
