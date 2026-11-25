import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

function commonJsDeclaration(text) {
  const source = ts.createSourceFile('declaration.d.ts', text, ts.ScriptTarget.Latest, true);
  const printer = ts.createPrinter({ newLine: ts.NewLineKind.LineFeed });
  const replacements = source.statements
    .filter(
      (node) =>
        ts.isImportDeclaration(node) &&
        node.importClause &&
        !node.moduleSpecifier.text.startsWith('.') &&
        !node.moduleSpecifier.text.startsWith('/'),
    )
    .map((node) => {
      // 宣言内の外部importは型としてのみ使われる。ESM専用依存の型も明示した解決モードで読む。
      const clause = ts.factory.updateImportClause(
        node.importClause,
        true,
        node.importClause.name,
        node.importClause.namedBindings,
      );
      const attributes = ts.factory.createImportAttributes([
        ts.factory.createImportAttribute(
          ts.factory.createStringLiteral('resolution-mode'),
          ts.factory.createStringLiteral('import'),
        ),
      ]);
      const updated = ts.factory.updateImportDeclaration(
        node,
        node.modifiers,
        clause,
        node.moduleSpecifier,
        attributes,
      );
      return {
        start: node.getStart(source),
        end: node.end,
        text: printer.printNode(ts.EmitHint.Unspecified, updated, source),
      };
    });
  for (const replacement of replacements.reverse())
    text = text.slice(0, replacement.start) + replacement.text + text.slice(replacement.end);
  // 外部importの書換え後は元のcolumn mappingが成立しないので、CJS側へ古いmapを配布しない。
  return text.replace(/^\/\/# sourceMappingURL=.*$/gm, '');
}

/** .js相対参照の型グラフを維持し、パッケージ境界で全宣言をCommonJSとして扱う。 */
export function emitCjsTypes(dist) {
  const target = join(dist, 'cjs-types');
  rmSync(target, { recursive: true, force: true });
  const visit = (directory, relative = '') => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (relative === '' && entry.name === 'cjs-types') continue;
      const name = join(relative, entry.name);
      if (entry.isDirectory()) visit(join(directory, entry.name), name);
      else if (entry.isFile() && /\.d\.ts$/.test(entry.name)) {
        mkdirSync(dirname(join(target, name)), { recursive: true });
        writeFileSync(
          join(target, name),
          commonJsDeclaration(readFileSync(join(directory, entry.name), 'utf8')),
        );
      }
    }
  };
  visit(dist);
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, 'package.json'), '{"type":"commonjs"}\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  emitCjsTypes(fileURLToPath(new URL('../dist', import.meta.url)));
}
