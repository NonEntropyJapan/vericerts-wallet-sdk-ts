import { ts } from '../load-typescript.mjs';
import { accessedName, keyText, unwrap } from './ast-helpers.mjs';
import { DISABLING, RUNTIME_SKIPS, UNAMBIGUOUS } from './forms.mjs';
import { createCarrierTracker } from './ts-carriers.mjs';

const ENUMERATORS = new Set([
  'Object.values',
  'Object.entries',
  'Object.getOwnPropertyDescriptors',
  'Object.fromEntries',
]);
const KEYED = new Set([
  'Reflect.get',
  'Reflect.getOwnPropertyDescriptor',
  'Object.getOwnPropertyDescriptor',
]);
const literalKey = (node) => {
  const inner = unwrap(node);
  return ts.isStringLiteralLike(inner) ? inner.text : null;
};
export function scanCarriers({ sourceFile, classifier, runtimeNames, report, conditionOf, text }) {
  const isCarrier = (node) => classifier.isCarrierExpression(node);
  const runtimeTracker = createCarrierTracker(sourceFile, {
    isSeed: () => false,
    callArgsCarry: false,
    initial: [...runtimeNames].filter((name) => !classifier.roots.has(name)),
  });
  const isRuntime = (node) => {
    const inner = unwrap(node);
    return ts.isIdentifier(inner) && runtimeTracker.carriers.has(inner.text);
  };
  const reportKey = (element, key, names, prefix) => {
    if (key === undefined) return;
    if (ts.isComputedPropertyName(key)) {
      const literal = literalKey(key.expression);
      if (literal === null) report(element, '.dynamic', text(key.expression));
      else if (names.has(literal)) report(element, `${prefix}${literal}`);
    } else {
      const name = keyText(key);
      if (name !== null && names.has(name)) report(element, `${prefix}${name}`);
    }
  };
  const reportPattern = (pattern, initializer) => {
    const [names, prefix] = isRuntime(initializer)
      ? [RUNTIME_SKIPS, 'runtime:']
      : isCarrier(initializer)
        ? [DISABLING, '.']
        : [null, ''];
    if (names === null) return;
    for (const element of pattern.elements) {
      reportKey(element, element.propertyName ?? element.name, names, prefix);
    }
  };
  const visit = (node) => {
    const name = accessedName(node);
    if (
      name !== null &&
      UNAMBIGUOUS.has(name) &&
      !classifier.isRootExpression(node.expression) &&
      isCarrier(node.expression)
    ) {
      report(node, `.${name}`, conditionOf(node, name));
    } else if (
      name === null &&
      ts.isElementAccessExpression(node) &&
      !ts.isNumericLiteral(unwrap(node.argumentExpression)) &&
      isCarrier(node.expression)
    ) {
      report(node, '.dynamic', text(node.argumentExpression));
    }
    if (name !== null && RUNTIME_SKIPS.has(name) && runtimeTracker.carries(node.expression)) {
      report(node, `runtime:${name}`, conditionOf(node, name));
    }
    if (ts.isCallExpression(node)) visitCall(node);
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer !== undefined
    ) {
      reportPattern(node.name, node.initializer);
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isObjectLiteralExpression(node.left)
    ) {
      for (const property of node.left.properties) {
        if (ts.isShorthandPropertyAssignment(property)) {
          if (isCarrier(node.right) && DISABLING.has(property.name.text)) {
            report(property, `.${property.name.text}`);
          }
        } else if (ts.isPropertyAssignment(property) && isCarrier(node.right)) {
          reportKey(property, property.name, DISABLING, '.');
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  const visitCall = (call) => {
    const callee = unwrap(call.expression);
    if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.expression)) return;
    const api = `${callee.expression.text}.${callee.name.text}`;
    const [target, key] = call.arguments;
    if (target === undefined || !isCarrier(target)) return;
    if (KEYED.has(api)) {
      const literal = key === undefined ? null : literalKey(key);
      if (literal === null) report(call, '.dynamic', text(call));
      else if (DISABLING.has(literal)) report(call, `.${literal}`);
    } else if (ENUMERATORS.has(api)) {
      report(call, '.dynamic', text(call));
    }
  };
  visit(sourceFile);
}
