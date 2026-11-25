/**
 * アルゴリズムレジストリのプロトタイプ汚染耐性。
 *
 * 対応表は `Object.assign(Object.create(null), { … })` で保持する。
 * 通常のオブジェクトリテラルだと `ALGORITHM_SPECS['constructor']` が `Object.prototype.constructor`
 * を返し、`getAlgorithmSpec` の `spec === undefined` ガードが発火しない。その結果、未対応
 * アルゴリズムが `1030 UNSUPPORTED_ALGORITHM` ではなく素の `TypeError`（`createHasher` が
 * 関数でない）になり、fail-closed なエラー契約が壊れる。
 *
 * `parseContentHash` 経由ではこの経路に到達しない（alias 表の own key しか
 * `getAlgorithmSpec` に渡らない）ため、**公開 API `computeContentHash` の第 2 引数**という
 * 実際に到達可能な経路で検証する。ここを塞がないとテストが実質無効になる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getAlgorithmSpec, normalizeAlgorithmName } from '../algorithms.js';
import { computeContentHash } from '../verify.js';

const CONTENT = new TextEncoder().encode('vericerts artifact');

/** `Object.prototype` 上に存在し、対応表をリテラルにすると誤ヒットするキー。 */
const PROTOTYPE_KEYS = [
  'constructor',
  'toString',
  'valueOf',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toLocaleString',
  '__proto__',
] as const;

describe('getAlgorithmSpec: プロトタイプ汚染耐性', () => {
  it.each(
    PROTOTYPE_KEYS.map((key) => [key]),
  )('canonical 名 %s は 1030 で拒否する（Object.prototype にヒットしない）', (key) => {
    let thrown: unknown;
    try {
      getAlgorithmSpec(key as never);
    } catch (error) {
      thrown = error;
    }
    // リテラル実装だと spec が `Object.prototype.constructor` 等になり例外が出ない
    // （もしくは TypeError になる）ため、VericertsError であることまで確認する。
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
  });
});

describe('computeContentHash: プロトタイプ汚染耐性（公開 API 経由の到達経路）', () => {
  it.each(
    PROTOTYPE_KEYS.map((key) => [key]),
  )('algorithm=%s は 1030 で拒否する（TypeError にしない）', async (key) => {
    let thrown: unknown;
    try {
      await computeContentHash(CONTENT, key as never);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.UNSUPPORTED_ALGORITHM);
    // リテラル実装で実際に観測される失敗モードを名指しで塞ぐ。
    expect(thrown).not.toBeInstanceOf(TypeError);
  });

  it('対応アルゴリズムは引き続き計算できる（対照）', async () => {
    const parsed = await computeContentHash(CONTENT, 'sha2-256');
    expect(parsed.algorithm).toBe('sha2-256');
    expect(parsed.digest).toHaveLength(32);
  });
});

describe('normalizeAlgorithmName: プロトタイプ汚染耐性', () => {
  it.each(PROTOTYPE_KEYS.map((key) => [key]))('%s は undefined を返す', (key) => {
    expect(normalizeAlgorithmName(key)).toBeUndefined();
  });

  it('対応 alias は canonical 名を返す（対照）', () => {
    expect(normalizeAlgorithmName('SHA256')).toBe('sha2-256');
  });
});
