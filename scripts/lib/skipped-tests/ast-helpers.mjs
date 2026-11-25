import { ts } from '../load-typescript.mjs';

const OPTION_KEYS = new Set(['skip', 'todo', 'only']);
const SHRINKING_METHODS = new Set([
  'slice',
  'map',
  'filter',
  'flat',
  'flatMap',
  'sort',
  'reverse',
  'toSorted',
  'toReversed',
  'toSpliced',
  'with',
]);
const GROWING_METHODS = new Set(['push', 'unshift', 'splice', 'fill', 'copyWithin', 'set', 'add']);
const EACH_CALLEES = new Set(['each', 'for']);
const LITERAL_KINDS = new Set([
  ts.SyntaxKind.StringLiteral,
  ts.SyntaxKind.NoSubstitutionTemplateLiteral,
  ts.SyntaxKind.NumericLiteral,
  ts.SyntaxKind.TrueKeyword,
  ts.SyntaxKind.FalseKeyword,
  ts.SyntaxKind.NullKeyword,
]);
export const isFunctionLike = (node) => ts.isArrowFunction(node) || ts.isFunctionExpression(node);
export const isStringLike = (node) => ts.isStringLiteralLike(node) || ts.isTemplateExpression(node);
export function unwrap(node) {
  let current = node;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isNonNullExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}
export function accessedName(node) {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (
    ts.isElementAccessExpression(node) &&
    (ts.isStringLiteral(node.argumentExpression) ||
      ts.isNoSubstitutionTemplateLiteral(node.argumentExpression))
  ) {
    return node.argumentExpression.text;
  }
  return null;
}
export const keyText = (name) =>
  name !== undefined && (ts.isIdentifier(name) || ts.isStringLiteral(name)) ? name.text : null;
export function createConstAnalyzer(sourceFile) {
  const initializers = new Map();
  const mutated = new Set();
  const constants = new Map();
  const baseName = (node) => {
    let current = unwrap(node);
    while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
      current = unwrap(current.expression);
    }
    return ts.isIdentifier(current) ? current.text : null;
  };
  const index = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      const list = initializers.get(node.name.text) ?? [];
      list.push(node.initializer);
      initializers.set(node.name.text, list);
      if (
        ts.isVariableDeclarationList(node.parent) &&
        (node.parent.flags & ts.NodeFlags.Const) !== 0
      ) {
        constants.set(node.name.text, node.initializer);
      }
      const statement = node.parent?.parent;
      if (
        statement !== undefined &&
        ts.isVariableStatement(statement) &&
        ts.getModifiers?.(statement)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
      ) {
        mutated.add(node.name.text);
      }
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
    ) {
      const name = baseName(node.left);
      if (name !== null) mutated.add(name);
    }
    if (ts.isCallExpression(node)) {
      const callee = unwrap(node.expression);
      if (ts.isPropertyAccessExpression(callee) && GROWING_METHODS.has(callee.name.text)) {
        const name = baseName(callee.expression);
        if (name !== null) mutated.add(name);
      }
      const accessed = accessedName(callee);
      if (accessed === null || !EACH_CALLEES.has(accessed)) {
        for (const argument of node.arguments) {
          const name = baseName(ts.isSpreadElement(argument) ? argument.expression : argument);
          if (name !== null) mutated.add(name);
        }
      }
    }
    if (ts.isExportAssignment(node) || ts.isExportSpecifier(node)) {
      const name = ts.isExportAssignment(node)
        ? baseName(node.expression)
        : (node.propertyName ?? node.name).text;
      if (name !== null) mutated.add(name);
    }
    ts.forEachChild(node, index);
  };
  index(sourceFile);
  const resolveConst = (identifier) => {
    const list = initializers.get(identifier.text);
    return list?.length === 1 ? list[0] : undefined;
  };
  const resolveTable = (identifier) =>
    initializers.get(identifier.text)?.length === 1 && !mutated.has(identifier.text)
      ? constants.get(identifier.text)
      : undefined;
  const optionVerdict = (expression, strict, depth = 0) => {
    const node = unwrap(expression);
    if (depth > 4) return strict ? 'dynamic' : null;
    if (ts.isIdentifier(node)) {
      const resolved = resolveConst(node);
      if (resolved !== undefined) return optionVerdict(resolved, strict, depth + 1);
      return strict && node.text !== 'undefined' ? 'dynamic' : null;
    }
    if (ts.isObjectLiteralExpression(node)) {
      for (const property of node.properties) {
        if (ts.isSpreadAssignment(property)) {
          const verdict = optionVerdict(property.expression, strict, depth + 1);
          if (verdict !== null) return verdict;
          continue;
        }
        const name = property.name;
        if (name !== undefined && ts.isComputedPropertyName(name)) {
          if (strict) return 'dynamic';
          continue;
        }
        const key = keyText(name);
        if (key === null || !OPTION_KEYS.has(key)) continue;
        if (
          ts.isPropertyAssignment(property) &&
          property.initializer.kind === ts.SyntaxKind.FalseKeyword
        ) {
          continue;
        }
        return key;
      }
      return null;
    }
    if (!strict || isFunctionLike(node) || LITERAL_KINDS.has(node.kind)) return null;
    return 'dynamic';
  };
  const isFalsyLiteral = (node) => {
    const inner = unwrap(node);
    return (
      inner.kind === ts.SyntaxKind.FalseKeyword ||
      inner.kind === ts.SyntaxKind.NullKeyword ||
      (ts.isIdentifier(inner) && inner.text === 'undefined') ||
      (ts.isNumericLiteral(inner) && Number(inner.text) === 0) ||
      (ts.isStringLiteralLike(inner) && inner.text === '')
    );
  };
  const isAlwaysFalsy = (node) => {
    const fn = unwrap(node);
    if (!isFunctionLike(fn)) return false;
    if (!ts.isBlock(fn.body)) return isFalsyLiteral(fn.body);
    const [only, ...rest] = fn.body.statements;
    return (
      rest.length === 0 &&
      only !== undefined &&
      ts.isReturnStatement(only) &&
      only.expression !== undefined &&
      isFalsyLiteral(only.expression)
    );
  };
  const isZeroLength = (node) => {
    const inner = unwrap(node);
    return (
      ts.isObjectLiteralExpression(inner) &&
      inner.properties.some(
        (property) =>
          ts.isPropertyAssignment(property) &&
          keyText(property.name) === 'length' &&
          ts.isNumericLiteral(unwrap(property.initializer)) &&
          Number(unwrap(property.initializer).text) === 0,
      )
    );
  };
  const isArrayConstructor = (callee) => ts.isIdentifier(callee) && callee.text === 'Array';
  const isEmptyTable = (expression, depth = 0) => {
    if (depth > 8) return false;
    const node = unwrap(expression);
    const empty = (child) => isEmptyTable(child, depth + 1);
    if (ts.isArrayLiteralExpression(node)) {
      return node.elements.every(
        (element) => ts.isSpreadElement(element) && empty(element.expression),
      );
    }
    if (ts.isIdentifier(node)) {
      const resolved = resolveTable(node);
      return resolved !== undefined && empty(resolved);
    }
    if (ts.isNewExpression(node) || ts.isCallExpression(node)) {
      const callee = unwrap(node.expression);
      const args = node.arguments ?? [];
      if (isArrayConstructor(callee)) {
        return args.length === 0 || (args.length === 1 && isZeroNumber(args[0]));
      }
      if (!ts.isPropertyAccessExpression(callee)) return false;
      const method = callee.name.text;
      const receiver = unwrap(callee.expression);
      if (ts.isIdentifier(receiver) && receiver.text === 'Array') {
        if (method === 'of') return args.length === 0;
        return method === 'from' && args.length > 0 && (isZeroLength(args[0]) || empty(args[0]));
      }
      if (ts.isIdentifier(receiver) && receiver.text === 'Object') {
        return (
          ['keys', 'values', 'entries'].includes(method) &&
          args.length === 1 &&
          ts.isObjectLiteralExpression(unwrap(args[0])) &&
          unwrap(args[0]).properties.length === 0
        );
      }
      if (method === 'filter')
        return empty(receiver) || (args.length > 0 && isAlwaysFalsy(args[0]));
      if (method === 'concat') return empty(receiver) && args.every((argument) => empty(argument));
      return SHRINKING_METHODS.has(method) && empty(receiver);
    }
    return false;
  };
  const isZeroNumber = (node) => {
    const inner = unwrap(node);
    return ts.isNumericLiteral(inner) && Number(inner.text) === 0;
  };
  return { optionVerdict, isEmptyTable };
}
