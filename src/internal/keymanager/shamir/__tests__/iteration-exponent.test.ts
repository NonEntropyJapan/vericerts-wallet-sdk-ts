/**
 * 復旧時の iterationExponent 上限。
 *
 * 指数は 4bit でシェア文字列に載り、RS1024 チェックサムは公開アルゴリズムなので再計算できる。
 * 上限が無いと改変シェア 1 語で `recoverMnemonic`（同期 PBKDF2）を分単位でブロックできる。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../__tests__/heavy-input-timeout.js';
import { createShares, recoverMnemonic } from '../index.js';
import { shareFromMnemonic, shareToMnemonic } from '../share.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** 全シェアの iterationExponent だけを書き換え、チェックサムを再計算して再エンコードする。 */
function withExponent(shares: readonly string[], iterationExponent: number): string[] {
  return shares.map((mnemonic) =>
    shareToMnemonic({ ...shareFromMnemonic(mnemonic), iterationExponent }),
  );
}

describe('recoverMnemonic — iterationExponent の上限', () => {
  const { shares } = createShares(MNEMONIC, 2, 3);

  it('この SDK が生成したシェアは復旧できる', () => {
    expect(recoverMnemonic(shares.slice(0, 2))).toEqual({ status: 'success', mnemonic: MNEMONIC });
  });

  it('iterationExponent: 15 のシェア群は PBKDF2 に入らず即座に invalid_share になる', () => {
    const forged = withExponent(shares.slice(0, 2), 15);
    const startedAt = performance.now();
    expect(recoverMnemonic(forged)).toEqual({ status: 'invalid_share' });
    expect(performance.now() - startedAt).toBeLessThan(100);
  });

  it('上限（4）を 1 超える 5 は拒否し、上限ちょうどは復号まで進む（digest 不一致で invalid_share）', () => {
    expect(recoverMnemonic(withExponent(shares.slice(0, 2), 5))).toEqual({
      status: 'invalid_share',
    });
    const startedAt = performance.now();
    expect(recoverMnemonic(withExponent(shares.slice(0, 2), 4))).toEqual({
      status: 'invalid_share',
    });
    // 上限内は PBKDF2 まで進むため、上限超過の即時拒否より明らかに遅い（が数秒以内に終わる）。
    expect(performance.now() - startedAt).toBeLessThan(5_000);
  });

  it('1 枚だけ改変した混在も拒否する', () => {
    const [a, b] = shares as [string, string];
    const forged = [a, ...withExponent([b], 15)];
    expect(recoverMnemonic(forged)).toEqual({ status: 'invalid_share' });
  });
});
