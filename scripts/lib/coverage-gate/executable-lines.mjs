import { ts } from '../load-typescript.mjs';

function isTypeOnly(node) {
  if (
    ts.isInterfaceDeclaration(node) ||
    ts.isTypeAliasDeclaration(node) ||
    ts.isImportDeclaration(node) ||
    ts.isImportEqualsDeclaration(node) ||
    ts.isExportDeclaration(node) ||
    ts.isEmptyStatement(node) ||
    ts.isBlock(node) ||
    ts.isNamespaceExportDeclaration(node)
  ) {
    return true;
  }
  return (ts.getCombinedModifierFlags(node) & ts.ModifierFlags.Ambient) !== 0;
}
function isCountedStatement(node) {
  return (
    (ts.isStatement(node) && !isTypeOnly(node)) ||
    (ts.isClassElement(node) &&
      (!ts.isPropertyDeclaration(node) || node.initializer !== undefined)) ||
    ts.isExportAssignment(node)
  );
}
export function countExecutableLines(text, kind = 'ts') {
  const scriptKind = {
    ts: ts.ScriptKind.TS,
    tsx: ts.ScriptKind.TSX,
    js: ts.ScriptKind.JS,
    jsx: ts.ScriptKind.JSX,
  }[kind];
  const sf = ts.createSourceFile(`x.${kind}`, text, ts.ScriptTarget.Latest, true, scriptKind);
  const lines = new Set();
  const visit = (node) => {
    if (isCountedStatement(node)) {
      lines.add(sf.getLineAndCharacterOfPosition(node.getStart(sf)).line);
    }
    if (ts.isTypeNode(node)) return;
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return lines.size;
}
export function executableLinesOf(file, text) {
  return countExecutableLines(
    text,
    file.endsWith('.tsx') ? 'tsx' : file.endsWith('.js') ? 'js' : 'ts',
  );
}
