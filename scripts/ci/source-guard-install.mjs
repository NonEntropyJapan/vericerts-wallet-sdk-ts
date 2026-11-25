import { ts } from '../lib/load-typescript.mjs';

// The dedicated Node boundary installer hands its prototype to this one bootstrap guard.
export function isCjsLoadGuardInstall(node, source, symbol) {
  if (
    !ts.isPropertyAccessExpression(node) ||
    node.questionDotToken ||
    node.name.text !== 'prototype' ||
    !ts.isIdentifier(node.expression) ||
    node.expression.text !== 'Module'
  )
    return false;
  const call = node.parent;
  if (
    !ts.isCallExpression(call) ||
    call.questionDotToken ||
    !ts.isExpressionStatement(call.parent) ||
    !ts.isIdentifier(call.expression) ||
    call.expression.text !== 'installCjsLoadGuard' ||
    call.arguments.length !== 3 ||
    call.arguments[0] !== node
  )
    return false;
  const body = call.parent.parent;
  const installer = body.parent;
  if (
    !ts.isBlock(body) ||
    !ts.isFunctionDeclaration(installer) ||
    installer.parent !== source ||
    installer.body !== body ||
    installer.name?.text !== 'installNodeBoundary' ||
    !installer.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
  )
    return false;
  const [, root, recorder] = call.arguments;
  if (
    !ts.isIdentifier(root) ||
    root.text !== 'root' ||
    !ts.isPropertyAccessExpression(recorder) ||
    recorder.questionDotToken ||
    recorder.name.text !== 'record' ||
    !ts.isIdentifier(recorder.expression) ||
    recorder.expression.text !== 'cjsViolations'
  )
    return false;
  const [moduleImport] = symbol(node.expression)?.declarations ?? [];
  const [guardImport] = symbol(call.expression)?.declarations ?? [];
  return (
    !!moduleImport &&
    ts.isImportClause(moduleImport) &&
    !moduleImport.isTypeOnly &&
    moduleImport.parent.moduleSpecifier.text === 'node:module' &&
    !!guardImport &&
    ts.isImportSpecifier(guardImport) &&
    !guardImport.propertyName &&
    !guardImport.isTypeOnly &&
    !guardImport.parent.parent.isTypeOnly &&
    guardImport.parent.parent.parent.moduleSpecifier.text === './cjs-load-guard.mjs'
  );
}
