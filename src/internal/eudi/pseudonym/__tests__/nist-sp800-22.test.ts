/**
 * Pseudonym 派生結果の統計的独立性セルフチェック。
 *
 * 多数の RP 識別子から派生した Pseudonym 鍵バイト列を連結し、
 * そのビット列に対し、NIST SP 800-22 の基本統計検定を実行する:
 *
 * - 2.1 Frequency (Monobit) Test: 0/1 出現数が均衡していること。
 * - 2.3 Runs Test: 連（同一ビットの連続）の総数が期待値に整合すること。
 *
 * いずれも p-value ≥ 有意水準 α（NIST 推奨 0.01）で合格とする（NIST SP 800-22 Rev.1a §4.2.1）。
 * HKDF-SHA256 出力は擬似ランダムなので、決定論的な MASTER_SEED でも安定して合格する。
 */

import { describe, expect, test } from 'bun:test';
import { derivePseudonym } from '../derive.js';

/** NIST 推奨の有意水準（SP 800-22 Rev.1a §4.2.1）。 */
const ALPHA = 0.01;

/** テスト用の決定的な 32 バイトマスター種。 */
const MASTER_SEED = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);

/**
 * 相補誤差関数 erfc(x)。
 *
 * Abramowitz & Stegun 7.1.26 の有理近似（|誤差| ≤ 1.5e-7）。NIST SP 800-22 の
 * p-value 算出に必要。x < 0 は erfc(-x) = 2 - erfc(x) で折り返す。
 */
function erfc(x: number): number {
  const z = Math.abs(x);
  const t = 1 / (1 + 0.5 * z);
  const tau =
    t *
    Math.exp(
      -z * z -
        1.26551223 +
        t *
          (1.00002368 +
            t *
              (0.37409196 +
                t *
                  (0.09678418 +
                    t *
                      (-0.18628806 +
                        t *
                          (0.27886807 +
                            t *
                              (-1.13520398 +
                                t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))),
    );
  return x >= 0 ? tau : 2 - tau;
}

/**
 * 多数の RP から派生した Pseudonym 秘密鍵バイト列を連結し、ビット列（0/1 配列）を得る。
 *
 * 検定対象は HKDF-SHA256 の生出力である privateKey(32B) のみとする。publicKey は圧縮点の
 * 先頭バイト（0x02/0x03）が定数に偏り monobit を歪めるため含めない（派生の統計的独立性は
 * HKDF 出力そのもので評価すれば十分）。全 RP 分を結合し MSB 先頭のビット列へ展開する。
 * RP 識別子は決定的に生成する（テスト再現性のため）。
 */
function deriveBitStream(rpCount: number): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < rpCount; i++) {
    const key = derivePseudonym(`rp-${i}.example`, MASTER_SEED);
    bytes.push(...key.privateKey);
  }
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let b = 7; b >= 0; b--) {
      bits.push((byte >> b) & 1);
    }
  }
  return bits;
}

/**
 * NIST SP 800-22 §2.1 Frequency (Monobit) Test の p-value。
 *
 * s = Σ(2·bit - 1)、s_obs = |s| / √n、p = erfc(s_obs / √2)。
 */
function monobitPValue(bits: number[]): number {
  const n = bits.length;
  let s = 0;
  for (const bit of bits) {
    s += 2 * bit - 1;
  }
  const sObs = Math.abs(s) / Math.sqrt(n);
  return erfc(sObs / Math.SQRT2);
}

/**
 * NIST SP 800-22 §2.3 Runs Test の p-value。
 *
 * π = (Σbit)/n、V_n = 連の総数、p = erfc(|V_n - 2nπ(1-π)| / (2√(2n)·π(1-π)))。
 * 事前条件（|π - 0.5| < 2/√n）は monobit 合格時に満たされる。
 */
function runsPValue(bits: number[]): number {
  const n = bits.length;
  const ones = bits.reduce((acc, bit) => acc + bit, 0);
  const pi = ones / n;
  let vn = 1;
  for (let i = 1; i < n; i++) {
    if (bits[i] !== bits[i - 1]) {
      vn++;
    }
  }
  const denom = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
  return erfc(Math.abs(vn - 2 * n * pi * (1 - pi)) / denom);
}

describe('NIST SP 800-22 派生結果の統計的独立性セルフチェック', () => {
  // 400 RP × 32 バイト = 12800 バイト = 102400 ビット（NIST 推奨の n ≥ 100 を十分に満たす）。
  const RP_COUNT = 400;
  const bits = deriveBitStream(RP_COUNT);

  test('派生ビット列は 102400 ビット（十分な標本長）を持つ', () => {
    expect(bits.length).toBe(RP_COUNT * 32 * 8);
  });

  test('Frequency (Monobit) Test に合格する（p-value ≥ 0.01）', () => {
    expect(monobitPValue(bits)).toBeGreaterThanOrEqual(ALPHA);
  });

  test('Runs Test に合格する（p-value ≥ 0.01）', () => {
    expect(runsPValue(bits)).toBeGreaterThanOrEqual(ALPHA);
  });

  test('erfc は既知の基準値に一致する（検定関数の健全性）', () => {
    // erfc(0)=1, erfc(1)≈0.157299, erfc(-1)≈1.842701。
    expect(erfc(0)).toBeCloseTo(1, 6);
    expect(erfc(1)).toBeCloseTo(0.157299, 5);
    expect(erfc(-1)).toBeCloseTo(1.842701, 5);
  });
});
