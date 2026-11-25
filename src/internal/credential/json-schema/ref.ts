/**
 * JSON Schema の `$ref` 解決（ローカル JSON Pointer のみ）。再帰を含まない純粋ヘルパー。
 *
 * 解決コストは参照文字列の長さに比例するため、長さ上限と
 * 走査量の前払いで 1 回の検証内の総量を縛る。
 */

import { consumeScan, type EvaluationBudget, stringScanUnits } from './internals.js';
import type { JsonSchema } from './types.js';

/**
 * `$ref` 文字列の最大長（UTF-16 コード単位）。実在のスキーマの `$ref` は数十バイトで、
 * 1 MiB のスキーマ文書に 30 万文字の参照を置いて `resolveRef` の分割・デコードを何万回も
 * 走らせる DoSを断つ。超過は解決不能（違反）として扱う。
 */
export const MAX_REF_LENGTH = 1_024;

/**
 * ローカル JSON Pointer（`#` / `#/a/b`）で `$ref` を解決する。
 *
 * リモート `$ref`（`https://...`）は解決しない。スキーマ検証中に副次的なネットワーク取得を
 * 発生させないための意図的な制限で、呼び出し側は `undefined` を違反として報告する。
 *
 * @returns 解決したスキーマ（boolean スキーマ `true` / `false` を含む）。解決できなければ
 *          （不正なパーセントエンコードを含む）`undefined`。
 */
export function resolveRef(root: JsonSchema, ref: string): JsonSchema | boolean | undefined {
  if (ref === '#') {
    return root;
  }
  if (!ref.startsWith('#/')) {
    return undefined;
  }
  let node: unknown = root;
  for (const rawSegment of ref.slice(2).split('/')) {
    // `#/%` のような不正なパーセントエンコードで `decodeURIComponent` は `URIError` を投げる。
    // `validateAgainstSchema` は例外を投げない契約なので、解決不能として扱う。
    let decoded: string;
    try {
      decoded = decodeURIComponent(rawSegment);
    } catch {
      return undefined;
    }
    const segment = decoded.replace(/~1/g, '/').replace(/~0/g, '~');
    // プロトタイプチェーン経由の参照（`#/constructor/prototype` / `#/__proto__` 等）で
    // スキーマではない組み込みオブジェクトへ到達させないため、自身のプロパティのみを辿る。
    if (typeof node !== 'object' || node === null || !Object.hasOwn(node, segment)) {
      return undefined;
    }
    node = (node as Record<string, unknown>)[segment];
  }
  if (typeof node === 'boolean') {
    return node;
  }
  return typeof node === 'object' && node !== null ? (node as JsonSchema) : undefined;
}

/**
 * `$ref` の解決を走査量予算へ計上してから行う（評価のたびに呼ばれる解決コストの増幅対策）。
 *
 * `MAX_REF_LENGTH` を超える参照は何もせず解決不能とする。予算が足りなければ（`exhausted` が立ち）
 * 解決せず `undefined` を返すので、呼び出し側は違反として報告する。
 */
export function resolveRefCharged(
  root: JsonSchema,
  ref: string,
  budget: EvaluationBudget,
): JsonSchema | boolean | undefined {
  if (ref.length > MAX_REF_LENGTH || !consumeScan(budget, stringScanUnits(ref.length))) {
    return undefined;
  }
  return resolveRef(root, ref);
}
