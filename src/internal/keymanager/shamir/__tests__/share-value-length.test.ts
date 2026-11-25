/**
 * 復旧時のシェア値長・枚数の上限。
 *
 * シェア値長は RS1024 チェックサム（公開アルゴリズム）を再計算すれば任意に作れ、PBKDF2 / GF(256) 補間 / 多倍長整数
 * 変換のコストは値長に比例する。シェア 1 枚で `recoverMnemonic`（同期 PBKDF2）を数十秒占有できたため、
 * `createShares` が生成する長さ以外は復号（`decryptMasterSecret`）へ進めない。実時間ではなく
 * `decryptMasterSecret` の呼び出し回数（決定的カウンタ）で pin する。
 */

import { describe, expect, it, spyOn } from 'bun:test';
import * as cipherModule from '../cipher.js';
import { createShares, recoverMnemonic } from '../index.js';
import { shareFromMnemonic, shareToMnemonic } from '../share.js';

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/**
 * 閾値 1 のシェア 1 枚を、値長 `length` のバイト列で作る（チェックサムは再計算）。閾値 1 のシェアは値がそのまま
 * 暗号化済みマスターシークレットになるため、ダイジェスト検査を経ずに PBKDF2 まで到達する（攻撃者が作れる最小の入力）。
 */
function singleShareWithValueLength(shares: readonly string[], length: number): string[] {
  const share = shareFromMnemonic(shares[0] as string);
  const value = Uint8Array.from(
    { length },
    (_, i) => share.value[i % share.value.length] as number,
  );
  return [shareToMnemonic({ ...share, memberThreshold: 1, value })];
}

function decryptCalls(shares: readonly string[]): { status: string; calls: number } {
  const spy = spyOn(cipherModule, 'decryptMasterSecret');
  try {
    const result = recoverMnemonic(shares);
    return { status: result.status, calls: spy.mock.calls.length };
  } finally {
    spy.mockRestore();
  }
}

describe('recoverMnemonic — シェア値長の上限', () => {
  const { shares } = createShares(MNEMONIC, 2, 3);

  it('この SDK が生成したシェア（12 語）は復旧でき、復号は 1 回', () => {
    expect(decryptCalls(shares.slice(0, 2))).toEqual({ status: 'success', calls: 1 });
  });

  it('値長が正規（18 バイト）の閾値 1 シェアは復号まで進む（対照: 上限を超えたものだけが止まる）', () => {
    expect(decryptCalls(singleShareWithValueLength(shares, 18)).calls).toBe(1);
  });

  it('24 語（値 34 バイト）のシェアも復旧できる', () => {
    const mnemonic24 = `${'abandon '.repeat(23)}art`;
    const created = createShares(mnemonic24, 2, 3);
    expect(recoverMnemonic(created.shares.slice(0, 2))).toEqual({
      status: 'success',
      mnemonic: mnemonic24,
    });
  });

  it.each([
    20, 36, 40, 200, 4000,
  ])('値長 %i バイトのシェアは invalid_share で、復号（PBKDF2）に入らない', (length) => {
    const forged = singleShareWithValueLength(shares, length);
    expect(decryptCalls(forged)).toEqual({ status: 'invalid_share', calls: 0 });
  });

  it('巨大なニーモニック文字列は単語分割の前に拒否する', () => {
    const huge = `${'abandon '.repeat(200_000)}about`;
    expect(() => shareFromMnemonic(huge)).toThrow();
    expect(decryptCalls([huge, huge])).toEqual({ status: 'invalid_share', calls: 0 });
  });

  it('シェア枚数が 16 を超える入力は復号に入らない', () => {
    const many = Array.from({ length: 17 }, () => shares[0] as string);
    expect(decryptCalls(many)).toEqual({ status: 'invalid_share', calls: 0 });
  });
});
