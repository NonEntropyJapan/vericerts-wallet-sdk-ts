/**
 * オブジェクトのキー列挙を 1 回の検証（= 1 つの {@link EvaluationBudget}）内でオブジェクトごとに
 * 1 回へ抑える。
 *
 * `Object.keys` はキー数に比例する。キー数は列挙するまで分からないため列挙そのものは前払いできず、
 * `allOf` / `enum` / `$ref` の多重化で同じインスタンスを何度も列挙させると、計上が列挙の後になる
 * 以上、評価ノード数の残量ぶん O(K) が繰り返される。結果を保持すれば実際の列挙は検証全体で
 * 「オブジェクト 1 つにつき 1 回（= 入力サイズに比例する 1 回）」に収まり、2 回目以降は計上済みの
 * 件数を読むだけになる。検証 1 回の間インスタンス・スキーマは変更されないため、保持は安全
 * （予算ごとのキャッシュなので、検証をまたいで古いキーを返すこともない）。
 */

import type { EvaluationBudget } from './internals.js';

/** オブジェクト 1 つ分の列挙結果。 */
export interface OwnKeys {
  /** 自身の列挙可能な文字列キー（`Object.keys` と同じ）。 */
  readonly keys: readonly string[];
  /** 全キーの文字数合計（違反 path の生成・キー走査の計上に使う）。 */
  readonly chars: number;
}

const cachesByBudget = new WeakMap<EvaluationBudget, WeakMap<object, OwnKeys>>();

/** `object` の自身のキーを返す。同じ予算の下では同じオブジェクトを再列挙しない。 */
export function ownKeysOf(budget: EvaluationBudget, object: object): OwnKeys {
  let cache = cachesByBudget.get(budget);
  if (cache === undefined) {
    cache = new WeakMap();
    cachesByBudget.set(budget, cache);
  }
  const cached = cache.get(object);
  if (cached !== undefined) {
    return cached;
  }
  const keys = Object.keys(object);
  let chars = 0;
  for (const key of keys) {
    chars += key.length;
  }
  const entry: OwnKeys = { keys, chars };
  cache.set(object, entry);
  return entry;
}
