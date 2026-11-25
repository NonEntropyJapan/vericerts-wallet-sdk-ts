import { readFileSync, statSync } from 'node:fs';
import { ts } from '../load-typescript.mjs';
import { boundNames, createCarrierTracker } from './ts-carriers.mjs';
import {
  AMBIGUOUS_ROOTS,
  isRelative,
  loadedModule,
  MAX_DEPTH,
  parseSource,
  ROOT_FACTORIES,
  resolveRelative,
  rootNames,
  TEST_MODULES,
  TEST_ROOTS,
} from './ts-source.mjs';

export { parseSource, rootNames, TEST_ROOTS };

const exportCache = new Map();
function exportedTestNames(file, depth, visiting) {
  let stamp;
  try {
    const stat = statSync(file);
    stamp = `${file}:${stat.mtimeMs}:${stat.size}`;
  } catch {
    return null;
  }
  if (exportCache.has(stamp)) return exportCache.get(stamp);
  if (visiting.has(file) || depth > MAX_DEPTH) return new Map();
  let source;
  try {
    source = readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  const sourceFile = parseSource(source, file);
  const nested = new Set(visiting).add(file);
  const classifier = createClassifier(sourceFile, file, depth + 1, nested, true);
  const names = new Map();
  const kindOf = (name) => classifier.kindOf(name);
  const addKind = (exportedName, kind) => {
    if (kind !== 'other' && names.get(exportedName) !== 'root') names.set(exportedName, kind);
  };
  const reExport = (spec, pick) => {
    const target = isRelative(spec) ? resolveRelative(file, spec) : null;
    const inner = target === null ? null : exportedTestNames(target, depth + 1, nested);
    if (inner !== null) pick(inner);
  };
  for (const statement of sourceFile.statements) {
    const modifiers = ts.getModifiers?.(statement) ?? [];
    const exported = modifiers.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
    const isDefault = modifiers.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword);
    if (ts.isVariableStatement(statement) && exported) {
      for (const declaration of statement.declarationList.declarations) {
        for (const name of boundNames(declaration.name)) addKind(name, kindOf(name));
      }
    } else if (ts.isFunctionDeclaration(statement) && exported && statement.name !== undefined) {
      addKind(isDefault ? 'default' : statement.name.text, kindOf(statement.name.text));
    } else if (ts.isExportDeclaration(statement)) {
      const spec = statement.moduleSpecifier;
      const clause = statement.exportClause;
      if (spec !== undefined && ts.isStringLiteral(spec)) {
        if (clause === undefined || ts.isNamespaceExport(clause)) {
          reExport(spec.text, (inner) => {
            for (const [name, kind] of inner) if (name !== 'default') addKind(name, kind);
            if (clause !== undefined && inner.size > 0) addKind(clause.name.text, 'root');
          });
        } else {
          for (const element of clause.elements) {
            reExport(spec.text, (inner) => {
              addKind(
                element.name.text,
                inner.get((element.propertyName ?? element.name).text) ?? 'other',
              );
            });
          }
        }
      } else if (clause !== undefined && ts.isNamedExports(clause)) {
        for (const element of clause.elements) {
          addKind(element.name.text, kindOf((element.propertyName ?? element.name).text));
        }
      }
    } else if (ts.isExportAssignment(statement)) {
      addKind(
        'default',
        classifier.isRootExpression(statement.expression)
          ? 'root'
          : classifier.isCarrierExpression(statement.expression)
            ? 'carrier'
            : 'other',
      );
    }
  }
  exportCache.set(stamp, names);
  return names;
}
export function createClassifier(
  sourceFile,
  fileName,
  depth = 0,
  visiting = new Set(),
  strict = false,
) {
  const roots = new Set(
    strict ? [...TEST_ROOTS].filter((name) => !AMBIGUOUS_ROOTS.has(name)) : TEST_ROOTS,
  );
  const imports = new Map();
  const bindModule = (local, imported, spec) => {
    if (TEST_MODULES.has(spec)) {
      if (imported === '*' || imported === 'default' || TEST_ROOTS.has(imported)) roots.add(local);
    } else {
      imports.set(local, { spec, imported });
      if (TEST_ROOTS.has(imported)) roots.add(local);
    }
  };
  for (const statement of sourceFile.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteral(statement.moduleSpecifier) ||
      statement.importClause === undefined
    ) {
      continue;
    }
    const spec = statement.moduleSpecifier.text;
    const clause = statement.importClause;
    if (clause.name !== undefined) bindModule(clause.name.text, 'default', spec);
    const named = clause.namedBindings;
    if (named !== undefined && ts.isNamedImports(named)) {
      for (const element of named.elements) {
        bindModule(element.name.text, (element.propertyName ?? element.name).text, spec);
      }
    } else if (named !== undefined && ts.isNamespaceImport(named)) {
      bindModule(named.name.text, '*', spec);
    }
  }
  const isRootName = (name) => classify(name) === 'root';
  const isRootExpression = (node) => {
    let inner = node;
    while (ts.isParenthesizedExpression(inner) || ts.isAwaitExpression(inner))
      inner = inner.expression;
    if (
      ts.isCallExpression(inner) &&
      ts.isIdentifier(inner.expression) &&
      ROOT_FACTORIES.has(inner.expression.text)
    ) {
      return inner.arguments.some(isRootExpression);
    }
    return rootNames(inner).some(isRootName);
  };
  const declarations = [];
  const collect = (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) declarations.push(node);
    ts.forEachChild(node, collect);
  };
  collect(sourceFile);
  for (let pass = 0; pass < 4; pass += 1) {
    const before = roots.size + imports.size;
    for (const declaration of declarations) {
      const spec = loadedModule(declaration.initializer);
      if (ts.isIdentifier(declaration.name)) {
        if (spec !== null) bindModule(declaration.name.text, '*', spec);
        else if (isRootExpression(declaration.initializer)) roots.add(declaration.name.text);
      } else if (ts.isObjectBindingPattern(declaration.name)) {
        for (const element of declaration.name.elements) {
          if (!ts.isIdentifier(element.name)) continue;
          const imported = (element.propertyName ?? element.name).getText(sourceFile);
          if (spec !== null) bindModule(element.name.text, imported, spec);
          else if (
            isRootExpression(declaration.initializer) &&
            (TEST_ROOTS.has(imported) ||
              element.dotDotDotToken !== undefined ||
              (element.propertyName !== undefined &&
                ts.isComputedPropertyName(element.propertyName)))
          ) {
            roots.add(element.name.text);
          }
        }
      }
    }
    if (roots.size + imports.size === before) break;
  }
  function classify(name) {
    if (roots.has(name)) return 'root';
    const imported = imports.get(name);
    if (imported === undefined) return 'other';
    if (!isRelative(imported.spec)) return 'unresolved';
    const target = resolveRelative(fileName, imported.spec);
    if (target === null) return 'unresolved';
    const names = exportedTestNames(target, depth, visiting);
    if (names === null) return 'unresolved';
    if (imported.imported === '*') {
      return names.size === 0 ? 'other' : [...names.values()].includes('root') ? 'root' : 'carrier';
    }
    return names.get(imported.imported) ?? 'other';
  }
  const isUnresolvedExpression = (node) =>
    !isRootExpression(node) && rootNames(node).some((name) => classify(name) === 'unresolved');
  const tracker = strict
    ? createCarrierTracker(sourceFile, {
        isSeed: isRootExpression,
        isExternal: (name) => classify(name) === 'carrier',
      })
    : createClassifier(sourceFile, fileName, depth, visiting, true);
  const kindOf = (name) =>
    classify(name) === 'root' ? 'root' : tracker.carriers.has(name) ? 'carrier' : classify(name);
  return {
    roots,
    carriers: tracker.carriers,
    isRootName,
    isRootExpression,
    isCarrierExpression: strict ? tracker.carries : tracker.isCarrierExpression,
    isUnresolvedExpression,
    kindOf,
  };
}
