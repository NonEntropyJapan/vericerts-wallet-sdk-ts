import { ts } from '../load-typescript.mjs';

const MUTATORS = new Set([
  'push',
  'unshift',
  'splice',
  'set',
  'add',
  'fill',
  'append',
  'assign',
  'defineProperty',
  'defineProperties',
]);
const ITERATORS = new Set([
  'forEach',
  'map',
  'flatMap',
  'filter',
  'find',
  'findLast',
  'some',
  'every',
  'reduce',
  'reduceRight',
  'then',
]);
const MAX_DEPTH = 24;
const unwrapValue = (node) => {
  let current = node;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isAwaitExpression(current)
  ) {
    current = current.expression;
  }
  return current;
};
export function boundNames(name) {
  if (ts.isIdentifier(name)) return [name.text];
  if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
    return name.elements.flatMap((element) =>
      ts.isOmittedExpression(element) ? [] : boundNames(element.name),
    );
  }
  return [];
}
function baseIdentifier(node) {
  let current = unwrapValue(node);
  while (
    ts.isPropertyAccessExpression(current) ||
    ts.isElementAccessExpression(current) ||
    ts.isCallExpression(current)
  ) {
    current = unwrapValue(current.expression);
  }
  return ts.isIdentifier(current) ? current.text : null;
}
export function createCarrierTracker(sourceFile, options) {
  const { isSeed, isExternal = () => false, callArgsCarry = true, initial = [] } = options;
  const carriers = new Set(initial);
  const functions = new Map();
  const isFunction = (node) =>
    ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node);
  function carries(node, depth = 0) {
    if (depth > MAX_DEPTH) return false;
    const next = (child) => carries(child, depth + 1);
    const current = unwrapValue(node);
    if (isSeed(current)) return true;
    if (ts.isIdentifier(current)) return carriers.has(current.text) || isExternal(current.text);
    if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
      return next(current.expression);
    }
    if (ts.isCallExpression(current) || ts.isNewExpression(current)) {
      return (
        next(current.expression) ||
        (callArgsCarry && (current.arguments ?? []).some((argument) => next(argument)))
      );
    }
    if (ts.isObjectLiteralExpression(current)) {
      return current.properties.some((property) => {
        if (ts.isPropertyAssignment(property)) return next(property.initializer);
        if (ts.isShorthandPropertyAssignment(property)) return next(property.name);
        if (ts.isSpreadAssignment(property)) return next(property.expression);
        return property.body !== undefined && returnsCarrier(property, depth);
      });
    }
    if (ts.isArrayLiteralExpression(current)) {
      return current.elements.some((element) =>
        next(ts.isSpreadElement(element) ? element.expression : element),
      );
    }
    if (ts.isConditionalExpression(current))
      return next(current.whenTrue) || next(current.whenFalse);
    if (ts.isBinaryExpression(current)) {
      const op = current.operatorToken.kind;
      if (op === ts.SyntaxKind.CommaToken || op === ts.SyntaxKind.EqualsToken)
        return next(current.right);
      return (
        (op === ts.SyntaxKind.BarBarToken ||
          op === ts.SyntaxKind.QuestionQuestionToken ||
          op === ts.SyntaxKind.AmpersandAmpersandToken) &&
        (next(current.left) || next(current.right))
      );
    }
    if (isFunction(current)) return returnsCarrier(current, depth);
    return false;
  }
  function returnsCarrier(fn, depth) {
    if (fn.body === undefined) return false;
    if (!ts.isBlock(fn.body)) return carries(fn.body, depth + 1);
    let found = false;
    const visit = (node) => {
      if (found) return;
      if (ts.isReturnStatement(node) && node.expression !== undefined) {
        found = carries(node.expression, depth + 1);
        return;
      }
      if (!isFunction(node)) ts.forEachChild(node, visit);
    };
    ts.forEachChild(fn.body, visit);
    return found;
  }
  const add = (names) => {
    let changed = false;
    for (const name of names) {
      if (!carriers.has(name)) {
        carriers.add(name);
        changed = true;
      }
    }
    return changed;
  };
  const rules = [];
  const parameterNames = (fn, index) =>
    fn.parameters.flatMap((parameter, position) =>
      position === index || (parameter.dotDotDotToken !== undefined && position < index)
        ? boundNames(parameter.name)
        : [],
    );
  const collect = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name !== undefined) {
      functions.set(node.name.text, [...(functions.get(node.name.text) ?? []), node]);
      rules.push(() => returnsCarrier(node, 0) && add([node.name.text]));
    }
    if (ts.isVariableDeclaration(node)) {
      const init = node.initializer;
      if (init !== undefined) {
        const target = unwrapValue(init);
        if (ts.isIdentifier(node.name) && isFunction(target)) {
          functions.set(node.name.text, [...(functions.get(node.name.text) ?? []), target]);
        }
        rules.push(() => carries(init) && add(boundNames(node.name)));
      } else if (
        ts.isVariableDeclarationList(node.parent) &&
        (ts.isForOfStatement(node.parent.parent) || ts.isForInStatement(node.parent.parent))
      ) {
        const loop = node.parent.parent;
        rules.push(() => carries(loop.expression) && add(boundNames(node.name)));
      }
    }
    if (ts.isParameter(node) && node.initializer !== undefined) {
      rules.push(() => carries(node.initializer) && add(boundNames(node.name)));
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      !ts.isObjectLiteralExpression(node.left)
    ) {
      const base = baseIdentifier(node.left);
      if (base !== null) rules.push(() => carries(node.right) && add([base]));
    }
    if (ts.isCallExpression(node)) collectCall(node);
    ts.forEachChild(node, collect);
  };
  const collectCall = (call) => {
    const callee = unwrapValue(call.expression);
    if (ts.isPropertyAccessExpression(callee)) {
      const method = callee.name.text;
      if (MUTATORS.has(method)) {
        const target = baseIdentifier(
          method === 'assign' ? (call.arguments[0] ?? callee) : callee.expression,
        );
        if (target !== null) {
          rules.push(() => call.arguments.some((argument) => carries(argument)) && add([target]));
        }
      }
      if (ITERATORS.has(method)) {
        for (const argument of call.arguments) {
          const fn = unwrapValue(argument);
          if (isFunction(fn)) {
            rules.push(
              () =>
                carries(callee.expression) && add(fn.parameters.flatMap((p) => boundNames(p.name))),
            );
          }
        }
      }
    }
    call.arguments.forEach((argument, index) => {
      rules.push(() => {
        const targets = isFunction(callee)
          ? [callee]
          : ts.isIdentifier(callee)
            ? (functions.get(callee.text) ?? [])
            : [];
        if (targets.length === 0 || !carries(argument)) return false;
        return targets.map((fn) => add(parameterNames(fn, index))).some(Boolean);
      });
    });
  };
  collect(sourceFile);
  for (let pass = 0; pass < 8; pass += 1) {
    let changed = false;
    for (const rule of rules) changed = rule() || changed;
    if (!changed) break;
  }
  return { carriers, carries: (node) => carries(node) };
}
