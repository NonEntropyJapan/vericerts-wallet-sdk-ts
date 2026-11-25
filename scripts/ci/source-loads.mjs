import path from 'node:path';
import { ts } from '../lib/load-typescript.mjs';
import {
  builtinNamespace,
  createStaticValue,
  destructuredCapability,
  importedCapability,
  isTypeOnlyExportSpecifier,
  loaderReexport,
  moduleMember,
  processMember,
  registrationAnchor,
} from './source-bindings.mjs';
import { isCjsLoadGuardInstall } from './source-guard-install.mjs';

const unbox = (node) => {
  while (
    node &&
    (ts.isParenthesizedExpression(node) ||
      ts.isAsExpression(node) ||
      ts.isTypeAssertionExpression(node) ||
      ts.isNonNullExpression(node) ||
      ts.isAwaitExpression(node))
  )
    node = node.expression;
  return node;
};
const property = (node) =>
  ts.isPropertyAccessExpression(node)
    ? node.name.text
    : ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)
      ? node.argumentExpression.text
      : null;

export function sourceLoads(source, file, relative) {
  const options = { allowJs: true, noLib: true, noResolve: true, target: ts.ScriptTarget.Latest };
  const host = ts.createCompilerHost(options);
  host.getSourceFile = (name) => (name === file ? source : undefined);
  const checker = ts.createProgram([file], options, host).getTypeChecker();
  const symbol = (node) => {
    if (ts.isExportSpecifier(node.parent))
      return checker.getExportSpecifierLocalTargetSymbol(node.parent);
    if (ts.isShorthandPropertyAssignment(node.parent) && node.parent.name === node)
      return checker.getShorthandAssignmentValueSymbol(node.parent);
    return checker.getSymbolAtLocation(node);
  };
  const assigned = new Map();
  function collect(node) {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      const key = symbol(node.left);
      if (key) assigned.set(key, [...(assigned.get(key) ?? []), node.right]);
    }
    ts.forEachChild(node, collect);
  }
  collect(source);
  function values(node) {
    const key = symbol(node);
    return [
      ...(key?.declarations ?? []).flatMap((declaration) => {
        if (ts.isVariableDeclaration(declaration) && declaration.initializer)
          return [declaration.initializer];
        return [];
      }),
      ...(assigned.get(key) ?? []),
    ];
  }
  function capability(input, seen = new Set()) {
    const node = unbox(input);
    if (!node || seen.has(node)) return null;
    seen = new Set([...seen, node]);
    if (ts.isIdentifier(node)) {
      const entry = importedCapability(node, symbol);
      if (entry) return entry;
      if (
        (!symbol(node)?.declarations?.length ||
          symbol(node)?.declarations?.every(
            (item) => ts.isVariableDeclaration(item) && !item.initializer,
          )) &&
        node.text === 'require'
      )
        return { kind: 'require', anchor: file };
      if (!symbol(node)?.declarations?.length && node.text === 'process')
        return { kind: 'process:namespace' };
      if (!symbol(node)?.declarations?.length && ['globalThis', 'global'].includes(node.text))
        return { kind: 'global:namespace' };
      if (!symbol(node)?.declarations?.length && node.text === 'module')
        return { kind: 'module:namespace' };
      for (const declaration of symbol(node)?.declarations ?? []) {
        const binding = destructuredCapability(
          declaration,
          (node) => capability(node, seen),
          staticValue,
          file,
        );
        if (binding) return binding;
      }
      const entries = values(node)
        .map((value) => capability(value, seen))
        .filter(Boolean);
      if (!entries.length) return null;
      if (new Set(entries.map((entry) => entry.kind)).size > 1) return { kind: 'ambiguous' };
      return entries[0];
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      if (node.getText(source) === 'import.meta.resolve') return { kind: 'resolve', anchor: file };
      const owner = capability(node.expression, seen);
      if (owner?.kind === 'ambiguous') return owner;
      const name =
        property(node) ??
        (ts.isElementAccessExpression(node) ? staticValue(node.argumentExpression) : null);
      if (owner?.kind === 'global:namespace' && name === 'require')
        return { kind: 'require', anchor: file };
      if (owner?.kind === 'global:namespace' && name === 'process')
        return { kind: 'process:namespace' };
      if (owner?.kind === 'process:namespace') return processMember(name);
      if (owner?.kind === 'module:namespace') return moduleMember(name, file);
      if (owner?.kind === 'require' && name === 'resolve') return { ...owner, kind: 'resolve' };
      if (
        ['factory', 'require', 'resolve', 'load', 'builtin-accessor'].includes(owner?.kind) &&
        ['call', 'apply', 'bind'].includes(name)
      )
        return { ...owner, method: name };
      if (['path:namespace', 'url:namespace'].includes(owner?.kind))
        return { kind: `${owner.kind.split(':')[0]}:${name}` };
    }
    if (ts.isCallExpression(node)) {
      const callee = capability(node.expression, seen);
      if (callee?.kind === 'ambiguous') return callee;
      if (callee?.method === 'bind') return { ...callee, method: undefined };
      if (callee?.kind === 'factory')
        return { kind: 'require', anchor: staticValue(callArguments(node, callee)[0]) };
      if (callee?.kind === 'builtin-accessor') {
        const name = staticValue(callArguments(node, callee)[0]);
        return name === undefined ? { kind: 'ambiguous' } : builtinNamespace(name);
      }
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword || callee?.kind === 'require')
        return builtinNamespace(staticValue(callArguments(node, callee)[0]));
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.CommaToken)
      return capability(node.right, seen);
    return null;
  }
  function callArguments(node, entry) {
    if (entry?.method === 'call') return [...node.arguments].slice(1);
    if (entry?.method === 'apply')
      return ts.isArrayLiteralExpression(node.arguments[1]) ? [...node.arguments[1].elements] : [];
    return [...node.arguments];
  }
  const staticValue = createStaticValue({ source, file, symbol, values, capability, unbox });
  const loads = [];
  for (const reference of source.referencedFiles)
    loads.push({
      node: source,
      argument: ts.factory.createStringLiteral(
        reference.fileName.startsWith('.') || path.isAbsolute(reference.fileName)
          ? reference.fileName
          : `./${reference.fileName}`,
      ),
      kind: 'type',
      anchor: file,
    });
  for (const reference of source.typeReferenceDirectives)
    loads.push({
      node: source,
      argument: ts.factory.createStringLiteral(
        reference.fileName.startsWith('.') || path.isAbsolute(reference.fileName)
          ? reference.fileName
          : `@types/${reference.fileName}`,
      ),
      kind: 'type',
      anchor: file,
    });
  function checkEscape(node) {
    if (ts.isIdentifier(node)) {
      const parent = node.parent;
      if (
        (ts.isVariableDeclaration(parent) && parent.name === node) ||
        ts.isImportSpecifier(parent) ||
        ts.isNamespaceImport(parent) ||
        ts.isImportClause(parent) ||
        (ts.isBindingElement(parent) && (parent.name === node || parent.propertyName === node)) ||
        (ts.isPropertyAccessExpression(parent) && parent.name === node)
      )
        return;
    }
    const entry = capability(node);
    if (
      ![
        'factory',
        'require',
        'resolve',
        'load',
        'module:namespace',
        'process:namespace',
        'builtin-accessor',
        'ambiguous',
      ].includes(entry?.kind)
    )
      return;
    let current = node;
    while (current.parent && unbox(current.parent) === current) current = current.parent;
    const parent = current.parent;
    if (!parent || ts.isImportDeclaration(parent) || ts.isImportEqualsDeclaration(parent)) return;
    if (
      (ts.isExportSpecifier(parent) && isTypeOnlyExportSpecifier(parent)) ||
      ts.isTypeQueryNode(parent) ||
      (entry.kind === 'process:namespace' && ts.isTypeOfExpression(parent)) ||
      (ts.isVariableDeclaration(parent) &&
        parent.initializer === current &&
        !parent.parent?.parent?.modifiers?.some(
          (item) => item.kind === ts.SyntaxKind.ExportKeyword,
        )) ||
      (ts.isPropertyAccessExpression(parent) && parent.expression === current) ||
      (ts.isElementAccessExpression(parent) && parent.expression === current) ||
      (ts.isCallExpression(parent) && parent.expression === current) ||
      (ts.isBinaryExpression(parent) &&
        [ts.SyntaxKind.EqualsToken, ts.SyntaxKind.CommaToken].includes(parent.operatorToken.kind) &&
        parent.right === current &&
        (parent.operatorToken.kind === ts.SyntaxKind.CommaToken || ts.isIdentifier(parent.left)))
    )
      return;
    if (
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      parent.left === current
    )
      loads.push({ node, argument: current, kind: 'mutation' });
    else if (
      relative !== 'scripts/packed-consumer/boundary-node.mjs' ||
      !isCjsLoadGuardInstall(node, source, symbol)
    )
      loads.push({ node, kind: 'unresolved' });
  }
  function visit(node) {
    if (
      ts.isIdentifier(node) ||
      ts.isCallExpression(node) ||
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    )
      checkEscape(node);
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier)
      loads.push({ node, argument: node.moduleSpecifier, kind: 'import', anchor: file });
    if (ts.isExportDeclaration(node) && loaderReexport(node))
      loads.push({ node, kind: 'unresolved' });
    if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference))
      loads.push({ node, argument: node.moduleReference.expression, kind: 'import', anchor: file });
    if (ts.isImportTypeNode(node))
      loads.push({
        node,
        argument: ts.isLiteralTypeNode(node.argument) ? node.argument.literal : node.argument,
        kind: 'type',
        anchor: file,
      });
    if (
      ts.isNewExpression(node) &&
      ['module:namespace', 'ambiguous', 'factory', 'require'].includes(
        capability(node.expression)?.kind,
      )
    )
      loads.push({ node, kind: 'unresolved' });
    if (ts.isCallExpression(node)) {
      const entry = capability(node.expression);
      if (entry?.method === 'bind' && node.arguments.length > 1)
        loads.push({ node, kind: 'unresolved' });
      if (
        ['ambiguous', 'module:namespace', 'process:namespace'].includes(entry?.kind) ||
        (entry?.kind === 'builtin-accessor' &&
          entry.method !== 'bind' &&
          staticValue(callArguments(node, entry)[0]) === undefined)
      )
        loads.push({ node, kind: 'unresolved' });
      else if (
        entry?.method !== 'bind' &&
        (['factory', 'require', 'resolve', 'load'].includes(entry?.kind) ||
          node.expression.kind === ts.SyntaxKind.ImportKeyword)
      ) {
        const args = callArguments(node, entry);
        const parent =
          entry?.kind === 'load' ? registrationAnchor(args[1], staticValue) : undefined;
        if (entry?.kind === 'load')
          loads.push({ node, argument: args[1], kind: 'factory', base: parent });
        loads.push({
          node,
          argument: args[0],
          kind: entry?.kind ?? 'import',
          anchor: entry?.kind === 'load' ? (parent ?? file) : (entry?.anchor ?? file),
          base: entry?.kind === 'factory' ? staticValue(args[0]) : undefined,
        });
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  return loads;
}
