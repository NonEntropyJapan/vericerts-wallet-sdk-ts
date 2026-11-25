import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { ts } from '../load-typescript.mjs';
export const TEST_ROOTS = new Set([
  'describe',
  'it',
  'test',
  'suite',
  'bench',
  'specify',
  'context',
]);
export const TEST_MODULES = new Set([
  'node:test',
  'bun:test',
  'vitest',
  '@playwright/test',
  '@jest/globals',
  'mocha',
  'jest',
]);
export const AMBIGUOUS_ROOTS = new Set(['context', 'suite', 'specify', 'bench']);
export const ROOT_FACTORIES = new Set(['mergeTests']);
export const GLOBAL_OBJECTS = new Set(['globalThis', 'global', 'window', 'self']);
export const MAX_DEPTH = 8;
export const SCRIPT_EXTS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];
const SCRIPT_KINDS = {
  '.ts': ts.ScriptKind.TS,
  '.mts': ts.ScriptKind.TS,
  '.cts': ts.ScriptKind.TS,
  '.tsx': ts.ScriptKind.TSX,
  '.jsx': ts.ScriptKind.JSX,
};
export function parseSource(source, fileName) {
  return ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    SCRIPT_KINDS[path.extname(fileName)] ?? ts.ScriptKind.JS,
  );
}
export function rootNames(node) {
  const names = [];
  const walk = (current) => {
    if (ts.isIdentifier(current)) {
      names.push(current.text);
    } else if (
      (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) &&
      ts.isIdentifier(current.expression) &&
      GLOBAL_OBJECTS.has(current.expression.text) &&
      TEST_ROOTS.has(
        ts.isPropertyAccessExpression(current)
          ? current.name.text
          : (current.argumentExpression.text ?? ''),
      )
    ) {
      names.push(
        ts.isPropertyAccessExpression(current)
          ? current.name.text
          : current.argumentExpression.text,
      );
    } else if (ts.isConditionalExpression(current)) {
      walk(current.whenTrue);
      walk(current.whenFalse);
    } else if (ts.isBinaryExpression(current)) {
      const op = current.operatorToken.kind;
      if (op === ts.SyntaxKind.CommaToken) walk(current.right);
      else if (
        op === ts.SyntaxKind.BarBarToken ||
        op === ts.SyntaxKind.QuestionQuestionToken ||
        op === ts.SyntaxKind.AmpersandAmpersandToken
      ) {
        walk(current.left);
        walk(current.right);
      }
    } else if (
      ts.isPropertyAccessExpression(current) ||
      ts.isElementAccessExpression(current) ||
      ts.isCallExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isTypeAssertionExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isAwaitExpression(current)
    ) {
      walk(current.expression);
    }
  };
  walk(node);
  return names;
}
export const isRelative = (spec) => spec.startsWith('./') || spec.startsWith('../');
export function resolveRelative(fromFile, spec) {
  const base = path.resolve(path.dirname(fromFile), spec);
  const stem = base.replace(/\.[cm]?[jt]sx?$/, '');
  const candidates = [
    base,
    ...SCRIPT_EXTS.map((ext) => base + ext),
    ...SCRIPT_EXTS.map((ext) => stem + ext),
    ...SCRIPT_EXTS.map((ext) => path.join(base, `index${ext}`)),
  ];
  return (
    candidates.find((candidate) => existsSync(candidate) && statSync(candidate).isFile()) ?? null
  );
}
export function loadedModule(initializer) {
  let node = initializer;
  while (ts.isAwaitExpression(node) || ts.isParenthesizedExpression(node)) node = node.expression;
  if (
    ts.isCallExpression(node) &&
    node.arguments.length === 1 &&
    ts.isStringLiteralLike(node.arguments[0]) &&
    ((ts.isIdentifier(node.expression) && node.expression.text === 'require') ||
      node.expression.kind === ts.SyntaxKind.ImportKeyword)
  ) {
    return node.arguments[0].text;
  }
  return null;
}
