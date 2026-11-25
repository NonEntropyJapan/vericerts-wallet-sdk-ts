/**
 * あるノードが**インスタンスの同じ位置に対して**必須と宣言するキーを、スキーマグラフから集める。
 *
 * `SchemaError.required` を分類する。`required` は JSON Schema の意味論ではスキーマ全体
 * （`allOf` / `$ref` の展開後）に効くので、`properties` と `required` が別ノードに分かれた合成
 * （`{allOf:[{properties:…},{required:[…]}]}` / `{$ref:…, required:[…]}`）でも必須として分類する。ノード自身の
 * `required` だけで分類すると、必須属性の型・形式違反が `required: false`（FO-4 の警告通過）に落ちる。
 *
 * ## 集める範囲
 *
 * ノード自身と、そこから**同じインスタンスへ評価が展開される**部分スキーマ（`$ref` の参照先・`allOf` / `anyOf` / `oneOf` の各枝）の
 * `required` の和集合。`anyOf` / `oneOf` はいずれかの枝が列挙したキーも必須に数える（fail-closed 側の近似: 「いずれかの形を満たすこと」
 * 自体が構造制約として `required: true` で報告される（`validate.ts`）のと同じ向き）。`not` は否定なので辿らない。
 * `properties` / `items` など別のインスタンス位置へ移る語彙は辿らない。
 *
 * ## 予算
 *
 * 走査は既存の走査量予算（`consumeScan`）へ**辿る前に**前払いする: 訪問ノード 1 つあたり 1 単位 + 各配列（`required` / `allOf` /
 * `anyOf` / `oneOf`）の要素数 + `$ref` の解決コスト（`resolveRefCharged`）。訪問済みノードは再訪しない（循環 `$ref` と、同じ部分スキーマを
 * 何度も指す `allOf` の多重化で時間が増えない）。予算が尽きたら途中の集合を返さず `undefined` を返し、`exhausted` で検証全体が
 * fail-closed になる。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import { consumeScan, type EvaluationBudget } from './internals.js';
import { resolveRefCharged } from './ref.js';
import type { JsonSchema } from './types.js';

/** 同じインスタンス位置へ展開される部分スキーマの配列キーワード。 */
const BRANCH_KEYWORDS = ['allOf', 'anyOf', 'oneOf'] as const;

function isSchemaObject(value: unknown): value is JsonSchema {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * `node` から辿れる `required` のキーの集合を返す。
 *
 * @param root `$ref` 解決の起点（ルートスキーマ）。
 * @param node 起点ノード。
 * @param budget 共有の走査量予算。
 * @returns 必須キーの集合。予算が尽きて集め切れなかったときは `undefined`（`budget.exhausted` が立つ）。
 */
export function collectRequiredKeys(
  root: JsonSchema,
  node: JsonSchema,
  budget: EvaluationBudget,
): ReadonlySet<string> | undefined {
  const keys = new Set<string>();
  const visited = new Set<JsonSchema>();
  const pending: JsonSchema[] = [node];
  while (pending.length > 0) {
    const current = pending.pop() as JsonSchema;
    if (visited.has(current)) {
      continue;
    }
    visited.add(current);
    if (!consumeScan(budget, 1)) {
      return undefined;
    }
    const required = ownProperty<unknown>(current, 'required');
    if (Array.isArray(required)) {
      if (!consumeScan(budget, required.length)) {
        return undefined;
      }
      for (const key of required) {
        if (typeof key === 'string') {
          keys.add(key);
        }
      }
    }
    const ref = ownProperty<unknown>(current, '$ref');
    if (typeof ref === 'string') {
      const target = resolveRefCharged(root, ref, budget);
      if (budget.exhausted) {
        return undefined;
      }
      // 解決できない `$ref` は評価側が違反として報告する。boolean スキーマは `required` を持たない。
      if (target !== undefined && typeof target !== 'boolean') {
        pending.push(target);
      }
    }
    for (const keyword of BRANCH_KEYWORDS) {
      const branches = ownProperty<unknown>(current, keyword);
      if (!Array.isArray(branches)) {
        continue;
      }
      if (!consumeScan(budget, branches.length)) {
        return undefined;
      }
      for (const branch of branches) {
        if (isSchemaObject(branch)) {
          pending.push(branch);
        }
      }
    }
  }
  return keys;
}

/**
 * 同じインスタンス位置へ展開されるノード群（入口ノードから `$ref` / `allOf` で辿った先）が共有する、必須キー集合の遅延計算。
 * 入口ノードで 1 回だけ集める（枝ごとに部分木を再走査しない）。
 */
export interface RequiredGroup {
  readonly entry: JsonSchema;
  keys?: ReadonlySet<string>;
}

/**
 * `group` の必須キー集合を返す（初回だけ {@link collectRequiredKeys} で集める）。
 * 予算が尽きたら `undefined`（呼び出し側は評価を打ち切る。`budget.exhausted` で検証全体が fail-closed になる）。
 */
export function requiredKeysOfGroup(
  ctx: { readonly root: JsonSchema; readonly budget: EvaluationBudget },
  group: RequiredGroup,
): ReadonlySet<string> | undefined {
  group.keys ??= collectRequiredKeys(ctx.root, group.entry, ctx.budget);
  return group.keys;
}
