/**
 * PEx `field.filter`（JSON Schema 風フィルタ）の評価。
 *
 * 評価できるのは `type` / `pattern` / `const` / `enum` /
 * `minimum` / `maximum` / `exclusiveMinimum` / `exclusiveMaximum` / `minLength` / `maxLength`。
 * それ以外の制約キーワードを持つ filter は `parsePresentationDefinition` が `unsatisfiable` として
 * 保持し、ここで不一致にする（黙って捨てて制約違反の VC をマッチさせない）。
 */

import {
  consumeScan,
  type EvaluationBudget,
  stringScanUnits,
} from '../credential/json-schema/internals.js';
import { deepEqual } from '../credential/json-schema/json-equal.js';
import { isPlainObject } from '../credential/object-guards.js';
import { compileSafeRegex, SafeRegexError } from '../primitives/safe-regex/index.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { PexBudget } from './budget.js';
import type { JSONSchemaFilter } from './filter-definition.js';

/** JSON Schema の `type` 相当の判定（`null` / `array` は typeof で表せないため個別に扱う）。 */
function matchesType(value: unknown, type: string): boolean {
  switch (type) {
    case 'null':
      return value === null;
    case 'array':
      return Array.isArray(value);
    case 'object':
      return isPlainObject(value);
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    default:
      return typeof value === type;
  }
}

/**
 * `pattern` のコンパイル結果を返す（予算 1 つの寿命の内ではソースごとに 1 回だけコンパイルする）。
 *
 * コンパイル費用はソース長に比例するとみなして正規表現ステップ予算から差し引く（JSON Schema 側の
 * `compilePattern` と同じ換算）。予算が足りなければコンパイルせず `too-complex` を投げる。失敗もメモし、
 * 同じ例外を投げ直す。
 *
 * @throws SafeRegexError コンパイルできない・予算超過。
 */
function compilePexPattern(pattern: string, budget: PexBudget) {
  const cached = budget.patterns.get(pattern);
  if (cached instanceof SafeRegexError) {
    throw cached;
  }
  if (cached !== undefined) {
    return cached;
  }
  if (budget.regex.remaining < pattern.length) {
    budget.regex.remaining = 0;
    throw new SafeRegexError('too-complex');
  }
  budget.regex.remaining -= pattern.length;
  budget.patternCompiles += 1;
  try {
    // PEx の `pattern` は従来ネイティブ `new RegExp(pattern)`（`u` なし）で評価されており、Verifier は
    // Annex B の寛容構文（`\:` / `[\w-.]` / リテラルの `{`）を送ってくる。JSON Schema 側
    // （`u` 固定）と違い、同じ意味論の非 `u` モードで評価する。後方参照・先読みは拒否のまま。
    const regex = compileSafeRegex(pattern, { unicode: false });
    budget.patterns.set(pattern, regex);
    return regex;
  } catch (error) {
    if (error instanceof SafeRegexError) {
      budget.patterns.set(pattern, error);
    }
    throw error;
  }
}

/**
 * `pattern` に値が一致するか。
 *
 * `pattern` は Verifier 由来の非信頼入力で、ネイティブ `RegExp` はマッチを中断できないため、
 * 線形時間エンジン（`safe-regex`）で評価する。構文不正・線形時間で扱えない構文
 * （後方参照・先読み）・長さ / 評価ステップ予算の超過は例外にせず fail-closed で不一致にする。
 */
function matchesPattern(value: unknown, pattern: string, budget: PexBudget): boolean {
  if (typeof value !== 'string') {
    return false;
  }
  try {
    return compilePexPattern(pattern, budget).test(value, budget.regex);
  } catch (error) {
    if (error instanceof SafeRegexError) {
      return false;
    }
    throw error;
  }
}

/** Unicode コードポイント数（JSON Schema の `minLength` / `maxLength` の単位）。 */
function codePointLength(value: string): number {
  let length = 0;
  for (const _ of value) {
    length += 1;
  }
  return length;
}

/**
 * 文字列の `minLength` / `maxLength` を満たすか（単位はコードポイント）。
 *
 * コードポイント数は UTF-16 長 `n` に対し `ceil(n / 2) <= 数 <= n` なので、この範囲だけで境界の判定が
 * 付くときは文字列を走査しない（`maxLength` が大きい・`minLength` が小さい通常の filter は O(1)）。
 * 範囲では決まらないときだけ全走査し、その走査量を `scan` 予算へ前払いする。使い切ったら不一致
 * （fail-closed。`scan.exhausted` が立つ）。
 */
function withinLengthBounds(value: string, filter: JSONSchemaFilter, scan: EvaluationBudget) {
  // 範囲キーワードは own に限って読む（`Object.prototype.minLength` 等の汚染で境界が変わらないように）。
  const minLength = ownProperty<number>(filter, 'minLength');
  const maxLength = ownProperty<number>(filter, 'maxLength');
  const upper = value.length;
  const lower = Math.ceil(upper / 2);
  if (
    (minLength !== undefined && upper < minLength) ||
    (maxLength !== undefined && lower > maxLength)
  ) {
    return false;
  }
  if (
    (minLength === undefined || lower >= minLength) &&
    (maxLength === undefined || upper <= maxLength)
  ) {
    return true;
  }
  if (!consumeScan(scan, stringScanUnits(upper))) {
    return false;
  }
  const length = codePointLength(value);
  return (
    (minLength === undefined || length >= minLength) &&
    (maxLength === undefined || length <= maxLength)
  );
}

/** 数値・文字列長の範囲キーワード。値が対象の型でなければ（JSON Schema と同じく）評価しない。 */
function withinBounds(value: unknown, filter: JSONSchemaFilter, scan: EvaluationBudget): boolean {
  if (typeof value === 'number') {
    const minimum = ownProperty<number>(filter, 'minimum');
    const maximum = ownProperty<number>(filter, 'maximum');
    const exclusiveMinimum = ownProperty<number>(filter, 'exclusiveMinimum');
    const exclusiveMaximum = ownProperty<number>(filter, 'exclusiveMaximum');
    return (
      (minimum === undefined || value >= minimum) &&
      (maximum === undefined || value <= maximum) &&
      (exclusiveMinimum === undefined || value > exclusiveMinimum) &&
      (exclusiveMaximum === undefined || value < exclusiveMaximum)
    );
  }
  if (
    typeof value === 'string' &&
    (ownProperty<number>(filter, 'minLength') !== undefined ||
      ownProperty<number>(filter, 'maxLength') !== undefined)
  ) {
    return withinLengthBounds(value, filter, scan);
  }
  return true;
}

/**
 * `value` が `candidates` のいずれかに深い等価で一致するか。
 *
 * 要素 1 件の比較（`deepEqual`）は入口で走査量を計上する。予算が尽きたら残りの要素は比較せず不一致にする
 * （尽きた後も全要素を回して、要素ごとの呼び出し固定費を無予算で払わない）。
 */
function matchesEnum(value: unknown, candidates: readonly unknown[], scan: EvaluationBudget) {
  for (let i = 0; i < candidates.length; i++) {
    if (scan.exhausted) {
      return false;
    }
    if (deepEqual(value, candidates[i], scan)) {
      return true;
    }
  }
  return false;
}

/**
 * `JSONSchemaFilter` を検証する。
 *
 * `const` / `enum` は JSON Schema と同じ深い等価で比較する。`value` は走査量予算付きの
 * ビューで、比較の走査量は {@link PexBudget} の `paths` / `scan` へ計上する。予算超過は
 * `PathBudgetExceededError`（`evaluateField` が握る）か `false`（`deepEqual`）で fail-closed になる。
 * `minLength` / `maxLength` の走査量・`pattern` のコンパイル費用も同じ予算へ計上する。
 */
export function matchesFilter(
  value: unknown,
  filter: JSONSchemaFilter,
  budget: PexBudget,
): boolean {
  if (ownProperty<boolean>(filter, 'unsatisfiable') === true || !matchesType(value, filter.type)) {
    return false;
  }
  const pattern = ownProperty<string>(filter, 'pattern');
  if (pattern !== undefined && !matchesPattern(value, pattern, budget)) {
    return false;
  }
  if (!withinBounds(value, filter, budget.scan)) {
    return false;
  }
  if (Object.hasOwn(filter, 'const') && !deepEqual(value, filter.const, budget.scan)) {
    return false;
  }
  const allowed = ownProperty<readonly unknown[]>(filter, 'enum');
  if (allowed !== undefined && !matchesEnum(value, allowed, budget.scan)) {
    return false;
  }
  return true;
}
