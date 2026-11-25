/**
 * JSON 値の等価判定（`enum` / `const` / `uniqueItems` 用）。再帰を含まない検証ロジックから分離した内部実装。
 *
 * 走査したノード数・文字数は評価量予算の走査量
 * （{@link consumeScan}）へ計上し、上限を超えたら `exhausted` を立てて fail-closed にする。
 * インスタンスの大きさに比例する走査を、スキーマの分岐増幅（`allOf` の多重化・`$ref` の再利用）で
 * 何度も繰り返させないため。
 */

import { consumeScan, type EvaluationBudget, stringScanUnits } from './internals.js';
import { ownKeysOf } from './own-keys.js';

/**
 * JSON 値の深い等価判定。ノードごとに走査量を計上し、予算を使い切ったら `false` を返す
 * （同時に `budget.exhausted` が立つので、検証全体が fail-closed になる）。
 */
export function deepEqual(a: unknown, b: unknown, budget: EvaluationBudget): boolean {
  const cost = typeof a === 'string' ? stringScanUnits(a.length) : 1;
  if (!consumeScan(budget, cost)) {
    return false;
  }
  if (a === b) {
    return true;
  }
  if (typeof a !== typeof b || a === null || b === null) {
    return false;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((item, i) => deepEqual(item, b[i], budget));
  }
  if (typeof a !== 'object') {
    return false;
  }
  // 両辺のキー列挙はオブジェクトごとに 1 回へ抑え、キー数は比較の前に走査量へ前払いする。
  // インスタンス側（`b`）の鍵数 K を、候補 1 つにつき 1 単位でしか計上せず何度も列挙していた。
  const aKeys = ownKeysOf(budget, a as object).keys;
  const bKeys = ownKeysOf(budget, b as object).keys;
  if (!consumeScan(budget, aKeys.length + bKeys.length)) {
    return false;
  }
  if (aKeys.length !== bKeys.length) {
    return false;
  }
  const bo = b as Record<string, unknown>;
  const ao = a as Record<string, unknown>;
  return aKeys.every((k) => Object.hasOwn(bo, k) && deepEqual(ao[k], bo[k], budget));
}

/**
 * `deepEqual` と同じ等価関係を保つ正規化 JSON（オブジェクトのキー順は無関係、配列は順序依存）。
 * 出力する文字数を走査量として計上する。
 *
 * @throws RangeError 走査量の予算を使い切った、またはネストが深すぎてスタックが尽きた。
 * @throws TypeError JSON 値ではない（`bigint` / 関数 / `undefined` 等）。
 */
function canonicalJson(value: unknown, budget: EvaluationBudget): string {
  if (Array.isArray(value)) {
    consumeScanOrThrow(budget, 2);
    return `[${value.map((item) => canonicalJson(item, budget)).join(',')}]`;
  }
  if (typeof value === 'object' && value !== null) {
    consumeScanOrThrow(budget, 2);
    const record = value as Record<string, unknown>;
    // キーのソート（K log K）は、その分を前払いしてから行う。
    const { keys } = ownKeysOf(budget, record);
    consumeScanOrThrow(budget, keys.length * Math.max(1, Math.ceil(Math.log2(keys.length + 1))));
    const members = [...keys].sort().map((key) => {
      // `JSON.stringify` はキー長に比例するため、先に長さを前払いする（エスケープ分は後で差額を計上）。
      consumeScanOrThrow(budget, key.length + 3);
      const encodedKey = JSON.stringify(key);
      consumeScanOrThrow(budget, encodedKey.length - key.length - 2);
      return `${encodedKey}:${canonicalJson(record[key], budget)}`;
    });
    return `{${members.join(',')}}`;
  }
  if (typeof value === 'string') {
    // 長さを先に前払いしてから `JSON.stringify` する。予算切れ後は文字列へ触れない。
    // 出力は `"` を含めて `length + 2` 文字以上で、エスケープ分は処理後に差額を計上する。
    consumeScanOrThrow(budget, value.length + 3);
    const encoded = JSON.stringify(value);
    consumeScanOrThrow(budget, encoded.length - value.length - 2);
    return encoded;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined || typeof value === 'bigint') {
    throw new TypeError('JSON 値ではありません');
  }
  consumeScanOrThrow(budget, encoded.length + 1);
  return encoded;
}

function consumeScanOrThrow(budget: EvaluationBudget, units: number): void {
  if (!consumeScan(budget, units)) {
    throw new RangeError('走査量が上限に達しました');
  }
}

/**
 * 配列に `deepEqual` で等しい要素の組があるか（`uniqueItems` 用、O(n) の 1 パス）。
 *
 * 各要素を正規化 JSON にして `Set` へ入れる。O(n²) の総当たりは 17 万要素（1 MiB 級）で約 20 秒
 * 同期処理を占有した。要素の大きさ（文字数）は走査量予算へ計上する。
 *
 * @throws TypeError 要素が JSON 値でない（`bigint` / 関数 / `undefined` 等）。
 * @throws RangeError 走査量の予算を使い切った、またはネストが深すぎてスタックが尽きた。
 */
export function hasDuplicateItems(items: readonly unknown[], budget: EvaluationBudget): boolean {
  const seen = new Set<string>();
  for (const item of items) {
    const key = canonicalJson(item, budget);
    if (seen.has(key)) {
      return true;
    }
    seen.add(key);
  }
  return false;
}
