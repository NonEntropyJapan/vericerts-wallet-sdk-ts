import { readFileSync } from 'node:fs';
import path from 'node:path';
import { ts } from '../load-typescript.mjs';
import {
  accessedName,
  createConstAnalyzer,
  isFunctionLike,
  isStringLike,
  keyText,
  unwrap,
} from './ast-helpers.mjs';
import { scanCarriers } from './carrier-scan.mjs';
import { DISABLING, RUNTIME_SKIPS, UNAMBIGUOUS } from './forms.mjs';
import { createClassifier, parseSource } from './ts-roots.mjs';

export { DISABLING as DISABLING_MODIFIERS };

const CONDITIONAL = new Set(['skipIf', 'runIf', 'if']);
const PREFIXED = new Set(['xit', 'xdescribe', 'xtest', 'fit', 'fdescribe', 'ftest']);
const TEST_MODULES = new Set([
  'node:test',
  'bun:test',
  'vitest',
  '@playwright/test',
  '@jest/globals',
  'mocha',
  'jest',
]);
const EACH_NAMES = new Set(['each', 'for']);
export function findDisabledTests(source, fileName) {
  const sourceFile = parseSource(source, fileName);
  const found = [];
  const lineOf = (node) => sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  const diagnostics = sourceFile.parseDiagnostics ?? [];
  if (diagnostics.length > 0) {
    found.push({
      line: sourceFile.getLineAndCharacterOfPosition(diagnostics[0].start ?? 0).line + 1,
      form: 'unparsable',
      condition: '',
    });
  }
  const classifier = createClassifier(sourceFile, path.resolve(fileName));
  const isRoot = (node) => classifier.isRootExpression(node);
  const isCarrier = (node) => classifier.isCarrierExpression(node);
  const text = (node) => node.getText(sourceFile).replace(/\s+/g, ' ').trim();
  const seen = new Set();
  const report = (node, form, condition = '') => {
    const key = `${node.getStart()}:${form}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ line: lineOf(node), form, condition });
  };
  const { optionVerdict, isEmptyTable } = createConstAnalyzer(sourceFile);
  const calledAs = (node) => {
    const parent = node.parent;
    return ts.isCallExpression(parent) && parent.expression === node ? parent : null;
  };
  const isDeclarationShape = (call) =>
    call.arguments.length > 1 &&
    isStringLike(unwrap(call.arguments[0])) &&
    call.arguments.slice(1).some((argument) => isFunctionLike(unwrap(argument)));
  const isDeclaration = (node, name) => {
    const call = calledAs(node);
    if (call === null) return false;
    if (isDeclarationShape(call)) return true;
    if (CONDITIONAL.has(name)) {
      const outer = calledAs(call);
      return outer !== null && isDeclarationShape(outer);
    }
    return false;
  };
  const conditionOf = (node, name) => {
    const call = calledAs(node);
    if (call === null) return '';
    const first = call.arguments[0];
    if (
      !CONDITIONAL.has(name) &&
      (first === undefined || isStringLike(unwrap(first)) || isFunctionLike(unwrap(first)))
    ) {
      return '';
    }
    return call.arguments.map(text).join(', ');
  };
  const runtimeNames = new Set();
  const visit = (node) => {
    const name = accessedName(node);
    if (name !== null && DISABLING.has(name)) {
      if (isRoot(node.expression)) {
        report(node, `.${name}`, conditionOf(node, name));
      } else if (
        UNAMBIGUOUS.has(name) &&
        calledAs(node) !== null &&
        (isDeclaration(node, name) || classifier.isUnresolvedExpression(node.expression))
      ) {
        report(node, `.${name}`, conditionOf(node, name));
      }
    } else if (ts.isElementAccessExpression(node) && name === null && isRoot(node.expression)) {
      report(node, '.dynamic', text(node.argumentExpression));
    }
    if (ts.isCallExpression(node)) visitCall(node);
    if (
      ts.isImportSpecifier(node) &&
      TEST_MODULES.has(node.parent.parent.parent.moduleSpecifier.text)
    ) {
      const imported = (node.propertyName ?? node.name).text;
      if (UNAMBIGUOUS.has(imported) || PREFIXED.has(imported)) report(node, `import:${imported}`);
    }
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer !== undefined
    ) {
      const loaded = testModuleLoad(node.initializer);
      if (loaded || isRoot(node.initializer)) {
        for (const element of node.name.elements) {
          const imported = (element.propertyName ?? element.name).getText(sourceFile);
          if (DISABLING.has(imported)) report(element, `.${imported}`);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  const testModuleLoad = (initializer) => {
    let node = initializer;
    while (ts.isAwaitExpression(node) || ts.isParenthesizedExpression(node)) node = node.expression;
    return (
      ts.isCallExpression(node) &&
      node.arguments.length === 1 &&
      ts.isStringLiteralLike(node.arguments[0]) &&
      TEST_MODULES.has(node.arguments[0].text)
    );
  };
  const visitCall = (node) => {
    const callee = node.expression;
    if (isRoot(callee)) {
      const lastFunction = node.arguments.findLastIndex((argument) =>
        isFunctionLike(unwrap(argument)),
      );
      node.arguments.forEach((argument, position) => {
        const strict = position >= 1 && position < lastFunction;
        const verdict =
          position === 0 && !ts.isObjectLiteralExpression(unwrap(argument))
            ? null
            : optionVerdict(argument, strict);
        if (verdict !== null)
          report(argument, `option:${verdict}`, optionCondition(argument, verdict));
        const body = unwrap(argument);
        if (isFunctionLike(body)) {
          for (const parameter of body.parameters) {
            if (ts.isIdentifier(parameter.name)) runtimeNames.add(parameter.name.text);
            else if (ts.isObjectBindingPattern(parameter.name)) {
              for (const element of parameter.name.elements) {
                const key = keyText(element.propertyName ?? element.name);
                if (element.dotDotDotToken !== undefined && ts.isIdentifier(element.name)) {
                  runtimeNames.add(element.name.text);
                } else if (key !== null && RUNTIME_SKIPS.has(key)) {
                  report(element, `runtime:${key}`);
                }
              }
            }
          }
        }
      });
    }
    const eachName = accessedName(callee);
    if (
      eachName !== null &&
      EACH_NAMES.has(eachName) &&
      isCarrier(callee.expression) &&
      node.arguments.length > 0 &&
      isEmptyTable(node.arguments[0])
    ) {
      report(node, 'each:empty');
    }
    if (
      ts.isIdentifier(callee) &&
      PREFIXED.has(callee.text) &&
      node.arguments.length > 0 &&
      isStringLike(node.arguments[0])
    ) {
      report(node, callee.text);
    }
  };
  const optionCondition = (argument, verdict) => {
    const node = unwrap(argument);
    if (verdict === 'dynamic' || !ts.isObjectLiteralExpression(node)) return text(argument);
    for (const property of node.properties) {
      if (keyText(property.name) === verdict) {
        return ts.isPropertyAssignment(property) ? text(property.initializer) : verdict;
      }
    }
    return text(argument);
  };
  visit(sourceFile);
  scanCarriers({ sourceFile, classifier, runtimeNames, report, conditionOf, text });
  return found.sort((a, b) => a.line - b.line);
}
export function findDisabledInFile(file) {
  return findDisabledTests(readFileSync(file, 'utf8'), file);
}
