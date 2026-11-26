import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ts } from '../lib/load-typescript.mjs';

export function createStaticValue({ source, file, symbol, values, capability, unbox }) {
  function staticValue(input, seen = new Set()) {
    const node = unbox(input);
    if (!node || seen.has(node)) return undefined;
    seen = new Set([...seen, node]);
    if (ts.isStringLiteralLike(node)) return node.text;
    if (node.getText(source) === 'import.meta.url') return pathToFileURL(file).href;
    if (ts.isIdentifier(node)) {
      if (!symbol(node)?.declarations?.length && node.text === '__filename') return file;
      if (!symbol(node)?.declarations?.length && node.text === '__dirname')
        return path.dirname(file);
      const resolved = values(node).map((value) => staticValue(value, seen));
      return resolved.length &&
        resolved.every((value) => value !== undefined && value === resolved[0])
        ? resolved[0]
        : undefined;
    }
    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'URL' &&
      !symbol(node.expression)
    ) {
      const args = (node.arguments ?? []).map((argument) => staticValue(argument, seen));
      if (args.every((value) => typeof value === 'string')) {
        try {
          return new URL(...args).href;
        } catch {
          return undefined;
        }
      }
    }
    if (ts.isCallExpression(node)) {
      const kind = capability(node.expression)?.kind;
      const args = node.arguments.map((argument) => staticValue(argument, seen));
      if (!args.every((value) => typeof value === 'string')) return undefined;
      if (['path:join', 'path:resolve', 'path:dirname'].includes(kind))
        return path[kind.split(':')[1]](...args);
      if (kind === 'url:fileURLToPath') {
        try {
          return fileURLToPath(args[0]);
        } catch {
          return undefined;
        }
      }
      if (
        node.expression.getText(source) === 'import.meta.resolve' &&
        ['@vericerts/vericerts-wallet-sdk', 'typescript'].includes(args[0])
      )
        return undefined;
    }
  }
  return staticValue;
}

export const isNodeModule = (name) => name === 'module' || name === 'node:module';
const nonLoadingMembers = new Set([
  'builtinModules',
  'constants',
  'isBuiltin',
  'syncBuiltinESMExports',
  'findPackageJSON',
  'stripTypeScriptTypes',
  'enableCompileCache',
  'flushCompileCache',
  'getCompileCacheDir',
  'SourceMap',
  'findSourceMap',
  'getSourceMapsSupport',
  'setSourceMapsSupport',
]);

export function moduleMember(name, file) {
  if (name === 'createRequire') return { kind: 'factory' };
  if (name === 'register') return { kind: 'load', anchor: file };
  if (name === 'require') return { kind: 'require', anchor: file };
  if (['default', 'Module', 'prototype'].includes(name)) return { kind: 'module:namespace' };
  return nonLoadingMembers.has(name) ? null : { kind: 'ambiguous' };
}
const isNodeProcess = (name) => name === 'process' || name === 'node:process';
export function processMember(name) {
  if (name == null) return { kind: 'ambiguous' };
  if (name === 'default') return { kind: 'process:namespace' };
  return name === 'getBuiltinModule' ? { kind: 'builtin-accessor' } : null;
}

export function builtinNamespace(name) {
  if (isNodeModule(name)) return { kind: 'module:namespace' };
  if (isNodeProcess(name)) return { kind: 'process:namespace' };
  return null;
}

export function destructuredCapability(declaration, resolve, staticValue, file) {
  if (!ts.isBindingElement(declaration)) return null;
  const container = declaration.parent.parent;
  const owner = ts.isBindingElement(container)
    ? destructuredCapability(container, resolve, staticValue, file)
    : resolve(container.initializer);
  if (owner?.kind === 'ambiguous') return owner;
  if (!['module:namespace', 'process:namespace'].includes(owner?.kind)) return null;
  if (!ts.isObjectBindingPattern(declaration.parent)) return { kind: 'ambiguous' };
  const member = declaration.propertyName ?? declaration.name;
  const name = ts.isComputedPropertyName(member) ? staticValue(member.expression) : member.text;
  if (owner.kind === 'module:namespace')
    return declaration.dotDotDotToken ? { kind: 'ambiguous' } : moduleMember(name, file);
  return declaration.dotDotDotToken ? owner : processMember(name);
}

export function importedCapability(node, symbol) {
  for (const declaration of symbol(node)?.declarations ?? []) {
    if (ts.isImportSpecifier(declaration)) {
      const origin = declaration.parent.parent.parent.moduleSpecifier?.text;
      const name = (declaration.propertyName ?? declaration.name).text;
      if (isNodeModule(origin)) return moduleMember(name);
      if (isNodeProcess(origin)) return processMember(name);
      if (['path', 'node:path', 'url', 'node:url'].includes(origin))
        return { kind: `${origin.replace('node:', '')}:${name}` };
    }
    if (ts.isNamespaceImport(declaration) || ts.isImportClause(declaration)) {
      const origin = (
        ts.isNamespaceImport(declaration) ? declaration.parent.parent : declaration.parent
      ).moduleSpecifier?.text;
      const builtin = builtinNamespace(origin);
      if (builtin) return builtin;
      if (['path', 'node:path', 'url', 'node:url'].includes(origin))
        return { kind: `${origin.replace('node:', '')}:namespace` };
    }
    if (
      ts.isImportEqualsDeclaration(declaration) &&
      ts.isExternalModuleReference(declaration.moduleReference)
    ) {
      const origin = declaration.moduleReference.expression?.text;
      return builtinNamespace(origin);
    }
  }
}

export function isTypeOnlyExportSpecifier(specifier) {
  return specifier.isTypeOnly || specifier.parent.parent.isTypeOnly;
}

export function loaderReexport(node) {
  const origin = node.moduleSpecifier?.text;
  const fromModule = isNodeModule(origin);
  if (node.isTypeOnly || (!fromModule && !isNodeProcess(origin))) return false;
  const clause = node.exportClause;
  return (
    !clause ||
    ts.isNamespaceExport(clause) ||
    clause.elements.some(
      (specifier) =>
        !isTypeOnlyExportSpecifier(specifier) &&
        (fromModule || processMember((specifier.propertyName ?? specifier.name).text)),
    )
  );
}

export function registrationAnchor(argument, staticValue) {
  if (!argument) return undefined;
  if (!ts.isObjectLiteralExpression(argument)) return staticValue(argument);
  const property = argument.properties.find(
    (item) => ts.isPropertyAssignment(item) && item.name?.text === 'parentURL',
  );
  return property ? staticValue(property.initializer) : undefined;
}
