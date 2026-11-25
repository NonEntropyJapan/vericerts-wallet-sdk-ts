import { ts } from '../load-typescript.mjs';

function loadTypescript() {
  return ts;
}
function scriptKindOf(typescript, fileName) {
  if (/\.tsx$/.test(fileName)) return typescript.ScriptKind.TSX;
  if (/\.(?:mjs|cjs|js)$/.test(fileName)) return typescript.ScriptKind.JS;
  return typescript.ScriptKind.TS;
}
function isTypeOnlyStatement(typescript, node) {
  const { SyntaxKind } = typescript;
  if (node.modifiers?.some((modifier) => modifier.kind === SyntaxKind.DeclareKeyword)) return true;
  switch (node.kind) {
    case SyntaxKind.InterfaceDeclaration:
    case SyntaxKind.TypeAliasDeclaration:
    case SyntaxKind.EmptyStatement:
      return true;
    case SyntaxKind.FunctionDeclaration:
      return node.body === undefined;
    case SyntaxKind.ImportDeclaration:
      return node.importClause !== undefined;
    case SyntaxKind.ExportDeclaration: {
      if (node.isTypeOnly) return true;
      if (node.moduleSpecifier === undefined) return true;
      const named = node.exportClause;
      return (
        named !== undefined &&
        named.kind === SyntaxKind.NamedExports &&
        named.elements.length > 0 &&
        named.elements.every((element) => element.isTypeOnly)
      );
    }
    case SyntaxKind.ModuleDeclaration:
      return (
        node.body !== undefined &&
        node.body.kind === SyntaxKind.ModuleBlock &&
        node.body.statements.every((statement) => isTypeOnlyStatement(typescript, statement))
      );
    default:
      return false;
  }
}
function parse(source, fileName) {
  const typescript = loadTypescript();
  const sourceFile = typescript.createSourceFile(
    fileName,
    source,
    typescript.ScriptTarget.Latest,
    false,
    scriptKindOf(typescript, fileName),
  );
  return { typescript, sourceFile, broken: sourceFile.parseDiagnostics?.length > 0 };
}
export function hasExecutableTypeScript(source, fileName) {
  const { typescript, sourceFile, broken } = parse(source, fileName);
  if (broken) return true;
  return sourceFile.statements.some((statement) => !isTypeOnlyStatement(typescript, statement));
}
const TEST_API_ROOTS = new Set(['describe', 'it', 'test', 'suite', 'bench']);
function calleeRoot(typescript, expression) {
  let current = expression;
  while (current) {
    if (typescript.isIdentifier(current)) return current.text;
    if (
      typescript.isPropertyAccessExpression(current) ||
      typescript.isElementAccessExpression(current)
    ) {
      current = current.expression;
    } else if (typescript.isCallExpression(current)) {
      current = current.expression;
    } else {
      return null;
    }
  }
  return null;
}
export function definesTests(source, fileName) {
  const { typescript, sourceFile, broken } = parse(source, fileName);
  if (broken) return false;
  let found = false;
  const visit = (node) => {
    if (found) return;
    if (
      typescript.isCallExpression(node) &&
      TEST_API_ROOTS.has(calleeRoot(typescript, node.expression))
    ) {
      found = true;
      return;
    }
    typescript.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}
export function hasValueExport(source, fileName) {
  const { typescript, sourceFile, broken } = parse(source, fileName);
  if (broken) return true;
  const { SyntaxKind } = typescript;
  const isExported = (statement) =>
    typescript
      .getModifiers?.(statement)
      ?.some((modifier) => modifier.kind === SyntaxKind.ExportKeyword) === true;
  if (
    sourceFile.statements.some(
      (statement) =>
        (isExported(statement) && !isTypeOnlyStatement(typescript, statement)) ||
        typescript.isExportAssignment(statement) ||
        (typescript.isExportDeclaration(statement) &&
          !statement.isTypeOnly &&
          !(
            statement.exportClause !== undefined &&
            typescript.isNamedExports(statement.exportClause) &&
            statement.exportClause.elements.length > 0 &&
            statement.exportClause.elements.every((element) => element.isTypeOnly)
          )),
    )
  ) {
    return true;
  }
  let commonJs = false;
  const visit = (node) => {
    if (commonJs) return;
    if (
      typescript.isBinaryExpression(node) &&
      node.operatorToken.kind === SyntaxKind.EqualsToken &&
      /^(?:module\.exports|exports)\b/.test(node.left.getText(sourceFile))
    ) {
      commonJs = true;
      return;
    }
    typescript.forEachChild(node, visit);
  };
  visit(sourceFile);
  return commonJs;
}
