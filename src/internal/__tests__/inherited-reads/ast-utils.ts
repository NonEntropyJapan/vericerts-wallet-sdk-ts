/** scan.ts が使う構文ヘルパ（括弧・アサーションの除去、`Object.hasOwn` ガードの判定、定数キーの取り出し）。 */

import type * as TS from 'typescript';

export type TypeScriptApi = typeof TS;

/** 括弧・`as` / `!` / `satisfies` / `<T>x` を剥がす。 */
export function peel(ts: TypeScriptApi, expression: TS.Expression): TS.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isTypeAssertionExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

/** 括弧・`!` を剥がしたうえで、`as T` / `<T>x` の型アサーションか（`(o as Required<O>).a` の検出に使う）。 */
export function isTypeAssertion(ts: TypeScriptApi, expression: TS.Expression): boolean {
  let current = expression;
  while (ts.isParenthesizedExpression(current) || ts.isNonNullExpression(current)) {
    current = current.expression;
  }
  return ts.isAsExpression(current) || ts.isTypeAssertionExpression(current);
}

/** `Object.hasOwn(receiver, 'key')` か。 */
function isHasOwnCall(
  ts: TypeScriptApi,
  node: TS.Expression,
  receiver: string,
  key: string,
): boolean {
  return (
    ts.isCallExpression(node) &&
    node.expression.getText() === 'Object.hasOwn' &&
    node.arguments[0]?.getText() === receiver &&
    node.arguments[1] !== undefined &&
    ts.isStringLiteralLike(node.arguments[1]) &&
    node.arguments[1].text === key
  );
}

/** `node` が `Object.hasOwn(receiver, 'key') ? node : …` の true 側、または `Object.hasOwn(receiver, 'key') && node` の右辺か。 */
export function isGuardedByHasOwn(
  ts: TypeScriptApi,
  node: TS.Node,
  receiver: string,
  key: string,
): boolean {
  for (let current: TS.Node = node; current.parent !== undefined; current = current.parent) {
    const parent = current.parent;
    if (
      ts.isConditionalExpression(parent) &&
      parent.whenTrue === current &&
      isHasOwnCall(ts, parent.condition, receiver, key)
    ) {
      return true;
    }
    if (
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken &&
      parent.right === current &&
      isHasOwnCall(ts, parent.left, receiver, key)
    ) {
      return true;
    }
  }
  return false;
}
