import assert from 'node:assert/strict';
import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import { createRequire, isBuiltin } from 'node:module';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { containedFile, inside, ownTypeScript } from './containment.mjs';

export function checkSdkSyntax(consumer, installed) {
  const ts = ownTypeScript(consumer);
  const root = realpathSync(installed);
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const packages = new Set([
    pkg.name,
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}),
  ]);
  const files = [];
  function collect(dir) {
    for (const item of readdirSync(dir, { withFileTypes: true })) {
      const file = containedFile(root, join(dir, item.name));
      if (item.isDirectory()) collect(file);
      else if (/\.(?:[cm]?js|d\.[cm]?ts)$/.test(item.name)) files.push(file);
    }
  }
  collect(join(root, 'dist'));
  for (const file of files) {
    const ast = ts.createSourceFile(
      file,
      readFileSync(file, 'utf8'),
      ts.ScriptTarget.Latest,
      true,
      /\.d\.[cm]?ts$/.test(file) ? ts.ScriptKind.TS : ts.ScriptKind.JS,
    );
    assert.equal(ast.parseDiagnostics.length, 0, 'Cannot parse packed module');
    const requireNames = new Set(['require']);
    const factoryNames = new Set(['createRequire']);
    for (const statement of ast.statements) {
      if (
        ts.isImportDeclaration(statement) &&
        ['module', 'node:module'].includes(statement.moduleSpecifier.text)
      ) {
        const bindings = statement.importClause?.namedBindings;
        if (bindings && ts.isNamedImports(bindings)) {
          for (const binding of bindings.elements) {
            if ((binding.propertyName ?? binding.name).text === 'createRequire')
              factoryNames.add(binding.name.text);
          }
        }
      }
    }
    const factory = (node) =>
      ts.isIdentifier(node)
        ? factoryNames.has(node.text)
        : ts.isPropertyAccessExpression(node) && node.name.text === 'createRequire';
    const requireCall = (node) =>
      ts.isIdentifier(node)
        ? requireNames.has(node.text)
        : ts.isPropertyAccessExpression(node) && node.name.text === 'require';
    function modulePath(argument) {
      if (ts.isStringLiteralLike(argument)) return argument.text;
      if (
        ts.isNewExpression(argument) &&
        ts.isIdentifier(argument.expression) &&
        argument.expression.text === 'URL' &&
        argument.arguments?.length === 2 &&
        ts.isStringLiteralLike(argument.arguments[0]) &&
        argument.arguments[1].getText(ast) === 'import.meta.url'
      ) {
        const url = new URL(argument.arguments[0].text, pathToFileURL(file));
        assert.equal(url.protocol, 'file:', 'Non-file module URL');
        return fileURLToPath(url);
      }
      throw new Error('Non-literal packed module binding');
    }
    function check(specifier, urlExpression = false) {
      assert.ok(
        typeof specifier === 'string' && specifier.length > 0,
        'Empty packed module specifier',
      );
      if (isBuiltin(specifier)) return;
      if (specifier.startsWith('file:')) {
        containedFile(root, fileURLToPath(specifier));
        return;
      }
      if (isAbsolute(specifier)) {
        assert.ok(urlExpression, 'Absolute packed module reference');
        containedFile(root, specifier);
        return;
      }
      if (specifier.startsWith('.')) {
        const target = resolve(dirname(file), specifier);
        assert.ok(inside(root, target), 'Packed module reference leaves SDK package');
        if (/\.d\.[cm]?ts$/.test(file)) return; // The own compiler checks TS extension substitution and actual files.
        containedFile(root, createRequire(file).resolve(specifier));
        return;
      }
      const name = specifier.startsWith('@')
        ? specifier.split('/').slice(0, 2).join('/')
        : specifier.split('/')[0];
      assert.ok(packages.has(name), 'Undeclared packed module dependency');
    }
    for (const reference of ast.referencedFiles) {
      const name = reference.fileName;
      check(
        !isAbsolute(name) && !name.startsWith('file:') && !name.startsWith('.')
          ? `./${name}`
          : name,
      );
    }
    for (const reference of ast.typeReferenceDirectives) {
      assert.ok(
        !isAbsolute(reference.fileName) && !reference.fileName.startsWith('file:'),
        'Absolute type reference',
      );
    }
    function visit(node) {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        if (ts.isIdentifier(node.initializer) && requireNames.has(node.initializer.text))
          requireNames.add(node.name.text);
        if (ts.isCallExpression(node.initializer) && factory(node.initializer.expression))
          requireNames.add(node.name.text);
      }
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier)
        check(node.moduleSpecifier.text);
      if (
        ts.isImportTypeNode(node) &&
        ts.isLiteralTypeNode(node.argument) &&
        ts.isStringLiteral(node.argument.literal)
      ) {
        check(node.argument.literal.text);
      }
      if (ts.isCallExpression(node)) {
        if (factory(node.expression)) {
          assert.ok(
            node.arguments.length === 1 &&
              ['import.meta.url', '__filename'].includes(node.arguments[0].getText(ast)),
            'createRequire base must be the packed module',
          );
        }
        if (
          node.expression.kind === ts.SyntaxKind.ImportKeyword ||
          requireCall(node.expression) ||
          (ts.isCallExpression(node.expression) && factory(node.expression.expression))
        ) {
          assert.ok(node.arguments.length > 0, 'Missing packed module argument');
          check(modulePath(node.arguments[0]), ts.isNewExpression(node.arguments[0]));
        }
      }
      ts.forEachChild(node, visit);
    }
    visit(ast);
  }
  return files.length;
}
