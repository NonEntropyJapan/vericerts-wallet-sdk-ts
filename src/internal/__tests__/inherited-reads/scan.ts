/**
 * 「外部入力由来の型のプロパティを素で読む」継承読みの検出器。
 *
 * `Object.prototype` が汚染された環境では、**呼び出し側が省略した**プロパティ（`opts.x` / `options?.x` /
 * `const { x } = opts`）が汚染値を拾い、検証・上限・最小開示の保証が緩む。外部入力の読みは `ownProperty` /
 * `nonObjectPrototypeProperty`（`internal/prototype-safety/own-property.ts`）か `Object.hasOwn` で行う規約だが、人手の棚卸しでは
 * 同型が 繰り返し取りこぼされた。そこで TypeScript の型情報で機械的に拾う。
 *
 * ## 検出規則（起点は「値の出所」ではなく「型」）
 *
 * 次をすべて満たす読みを違反とする。レシーバの出所（パラメータ・ループ変数・`this` のフィールド・呼び出し結果・ジェネリクス・
 * クロージャ・オブジェクトリテラルのメソッド）は問わない。
 *
 * 1. 読み方は、`P.name` / `P?.name` / `P['name']`（定数キー・リテラルユニオンのキー `o[k]`）/ 分割代入（`const { name } = P` /
 *    `function f({ name }: O)` / `for (const { name } of list)` / `list.map(({ name }) => …)` / ネスト）。
 * 2. 読むプロパティが「継承で埋まりうる」型: 省略可能（`?`）、または必須でも型が `T | undefined` を含む。
 *    `Required<O>` / `Readonly<Required<O>>`（このライブラリが own で組み立てた内部の写し）のプロパティは必須なので対象外。
 *    ただしレシーバが型アサーション（`(o as Required<O>).a`）のときは、写しではなく付け替えなので元の宣言で判定する。
 * 3. そのプロパティが、**呼び出し側・外部入力が供給しうる**ことが型から言える。次のいずれか:
 *    a. レシーバの根のパラメータ名が {@link OPTION_BAG_NAMES}（オプション袋。型が内部のものでも呼び出し側が組み立てる）、
 *       または `this.<オプション袋名>`。
 *    b. プロパティが、`publicEntries`（パッケージの公開 API の入口ファイル）が export する関数・クラスのパラメータ型から、
 *       プロパティ・配列要素・ユニオン・型引数・コールバックの引数を辿って到達できる型のメンバ（{@link ExternalProperties}）。
 *    c. プロパティが、`any` / `unknown` からの型の絞り込み（`JSON.parse(..) as T`、`await res.json() as T`、型述語 `x is T`、
 *       `const x: T = JSON.parse(..)`）の絞り込み先 T から辿って到達できる型のメンバ。`narrowedRequired` を有効にしたときは、
 *       絞り込み先のメンバは**必須宣言でも**対象にする（型は必須でも実体は外部 JSON のため。関数型の引数・戻り値は辿らない）。
 * 4. 書き込み（`P.x = …`）・`Object.hasOwn(P, 'x') ? P.x : …` / `Object.hasOwn(P, 'x') && P.x` の own 確認済みの読みではない。
 *
 * 判定しきれない読み（このライブラリが自分で作った写し・スナップショットの own 値）は、`allowlist.ts` に理由付きで 1 箇所に集める。
 *
 * ## 既知の限界（過信しない）
 *
 * - 動的キー（`P[key]`、`key: string`）・スプレッド（`{ ...P }`）・`in` 演算子は追わない。
 * - 型が `any` のレシーバ（`JSON.parse` の戻り値を型付けせずに読む）は型からは分からない。
 * - `.vue` の `<script>` は対象外。
 */

import type * as TS from 'typescript';
import { isGuardedByHasOwn, isTypeAssertion, peel, type TypeScriptApi } from './ast-utils.js';
import { ExternalProperties } from './public-properties.js';

export type { TypeScriptApi };

/** オプション袋として扱うパラメータ名（型が公開 API に現れなくても、呼び出し側が組み立てる入力として扱う）。 */
export const OPTION_BAG_NAMES: ReadonlySet<string> = new Set([
  'opts',
  'options',
  'deps',
  'config',
  'params',
  'input',
  'ctx',
  'spec',
  'init',
  'args',
  'settings',
]);

export interface InheritedRead {
  /** SDK ルートからの相対パス。 */
  readonly file: string;
  readonly line: number;
  /** 例: `opts.maxEntries` / `{ maxEntries } = opts`。 */
  readonly expression: string;
}

export interface ScanOptions {
  /** 公開 API の入口ファイルの `sdkRoot` からの相対パス（例: `src/index.ts`）。省略するとオプション袋の名前と型の絞り込みだけで検出する。 */
  readonly publicEntries?: readonly string[];
  /**
   * 旧規則（従来）: レシーバの根が関数パラメータである省略可能プロパティの読みだけを対象にする
   * （`any` / `unknown` の絞り込み先・必須 `T | undefined` も見ない）。extension が新規則（型起点）へ移行するまでの暫定。
   * 移行後に削除する。
   */
  readonly legacyParameterRoots?: boolean;
  /**
   * 規則 3c の絞り込み先（`JSON.parse(..) as T` / `x is T` / `const x: T = JSON.parse(..)`）の**必須**プロパティも対象にする。
   * 型は必須でも実体は外部 JSON で、省略した入力は汚染値で補われる。sdk は有効にする。extension は 600 箇所超の検出
   * （`message.type` / popup の応答など。個別の汚染検証が未了）が出るため、移行（各読みを実汚染で選別）が済むまで無効のまま。
   */
  readonly narrowedRequired?: boolean;
}

/** `expression` の定数のキー名（`.name` / `['name']`）。決まらなければ undefined。 */
function constantKey(ts: TypeScriptApi, node: TS.Node): string | undefined {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) {
    return node.argumentExpression.text;
  }
  return undefined;
}

/**
 * `sdkRoot/tsconfig.json` のプログラムを走査し、`src/`（テスト・fixtures を除く）の継承読みを返す。
 *
 * @param sdkRoot 走査する TypeScript パッケージのルートディレクトリの絶対パス。
 */
export function findInheritedReads(
  sdkRoot: string,
  ts: TypeScriptApi,
  scanOptions: ScanOptions = {},
): InheritedRead[] {
  // `node:fs` / `node:path` は使わない（extension は `types: []` のブラウザ文脈でこのファイルも型検査する）。
  const root = sdkRoot.replace(/\/+$/, '');
  const configPath = `${root}/tsconfig.json`;
  if (!ts.sys.fileExists(configPath)) {
    throw new Error(`tsconfig.json not found: ${configPath}`);
  }
  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const checker = program.getTypeChecker();
  const entries = (scanOptions.publicEntries ?? []).map((entry) => {
    const file = program.getSourceFile(`${root}/${entry}`);
    if (file === undefined) throw new Error(`publicEntries: ${entry} がプログラムに無い`);
    return file;
  });
  const srcPrefix = `${root}/src/`;
  const isScanned = (fileName: string): boolean =>
    fileName.startsWith(srcPrefix) && !/(__tests__|\.test\.ts$|\.fixtures?\.ts$)/.test(fileName);
  const scanned = program.getSourceFiles().filter((sf) => isScanned(sf.fileName));
  const external = new ExternalProperties(ts, checker);
  external.addPublicEntries(entries);
  const legacy = scanOptions.legacyParameterRoots === true;
  // 絞り込み先の型のメンバ（`narrowedRequired` のとき必須プロパティも継承読みの対象にする。規則 3c）。
  const narrowed = new ExternalProperties(ts, checker, true);
  const narrowedRequired = scanOptions.narrowedRequired === true;
  if (!legacy) {
    for (const sf of scanned) {
      external.addNarrowingTargets(sf);
      if (narrowedRequired) narrowed.addNarrowingTargets(sf);
    }
  }
  const found: InheritedRead[] = [];

  /** 式の根のオプション袋名（パラメータ名・`this.<名前>`）を、別名・プロパティ連鎖をたどって探す。パラメータ由来の根は '' を返す。 */
  const rootName = (expression: TS.Expression, depth = 0): string | undefined => {
    if (depth > 8) return undefined;
    const current = peel(ts, expression);
    if (ts.isIdentifier(current)) {
      const declaration = checker.getSymbolAtLocation(current)?.valueDeclaration;
      if (declaration === undefined) return undefined;
      if (ts.isParameter(declaration)) return current.text;
      if (
        ts.isVariableDeclaration(declaration) &&
        ts.isIdentifier(declaration.name) &&
        declaration.initializer !== undefined
      ) {
        return rootName(declaration.initializer, depth + 1);
      }
      if (ts.isBindingElement(declaration)) return bindingRoot(declaration, depth + 1);
      return undefined;
    }
    if (ts.isPropertyAccessExpression(current)) {
      if (current.expression.kind === ts.SyntaxKind.ThisKeyword) return current.name.text;
      return rootName(current.expression, depth + 1);
    }
    if (ts.isElementAccessExpression(current)) return rootName(current.expression, depth + 1);
    return undefined;
  };
  /** 分割代入の束縛の根（`const { a } = opts` の `a` を `a.b` と読むとき）。 */
  const bindingRoot = (element: TS.BindingElement, depth: number): string | undefined => {
    const pattern = element.parent.parent;
    if (ts.isParameter(pattern)) return ts.isIdentifier(pattern.name) ? pattern.name.text : '{}';
    if (ts.isVariableDeclaration(pattern) && pattern.initializer !== undefined) {
      return rootName(pattern.initializer, depth + 1);
    }
    return undefined;
  };
  /** `this.x` の根（`this`）を除いた、関数パラメータ起点か。旧規則（legacy）で使う。 */
  const isParameterRooted = (expression: TS.Expression, depth = 0): boolean => {
    if (depth > 8) return false;
    const current = peel(ts, expression);
    if (ts.isIdentifier(current)) {
      const declaration = checker.getSymbolAtLocation(current)?.valueDeclaration;
      if (declaration === undefined) return false;
      if (ts.isParameter(declaration)) return true;
      if (
        ts.isVariableDeclaration(declaration) &&
        ts.isIdentifier(declaration.name) &&
        declaration.initializer !== undefined
      ) {
        return isParameterRooted(declaration.initializer, depth + 1);
      }
      if (ts.isBindingElement(declaration)) {
        const pattern = declaration.parent.parent;
        if (ts.isParameter(pattern)) return true;
        return (
          ts.isVariableDeclaration(pattern) &&
          pattern.initializer !== undefined &&
          isParameterRooted(pattern.initializer, depth + 1)
        );
      }
      return false;
    }
    if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
      return isParameterRooted(current.expression, depth + 1);
    }
    return false;
  };

  const includesUndefined = (type: TS.Type): boolean =>
    type.isUnion() && type.types.some((t) => (t.flags & ts.TypeFlags.Undefined) !== 0);
  /**
   * 継承で埋まりうる読みか。対象は、呼び出し側が組み立てる入力の型（interface / 型リテラルの宣言 = `PropertySignature`）のメンバだけ。
   * クラスのインスタンスフィールド（`this.storage`、コンストラクタのパラメータプロパティ）はコンストラクタが own で定義する。
   * 省略可能（`?`）は、オプション袋・外部入力の型のどちらからでも対象。
   * 必須で型が `T | undefined` のプロパティは、外部入力の型のメンバであるときだけ対象にする
   * （オプション袋の名前だけでは、このライブラリが解決済みの写し `ResolvedDeps` の `T | undefined` まで拾ってしまう）。
   * 型アサーション越し（`(o as Required<O>).a`）は、アサーション先ではなく元の宣言で判定する。
   */
  const isInheritableRead = (
    symbol: TS.Symbol,
    bag: string | undefined,
    viaAssertion: boolean,
  ): boolean => {
    const reached = external.has(symbol);
    if (!reached && !(bag !== undefined && OPTION_BAG_NAMES.has(bag))) return false;
    const signatures = (symbol.declarations ?? []).filter(ts.isPropertySignature);
    if (signatures.length === 0) return false;
    const optional = viaAssertion
      ? signatures.some((d) => d.questionToken !== undefined)
      : (symbol.flags & ts.SymbolFlags.Optional) !== 0;
    if (optional) return true;
    if (legacy) return false;
    // `any` / `unknown` から絞り込んだ型（JSON.parse の結果・型述語）の必須プロパティも、実行時は欠落しうる。
    // 型だけの付け替え（`as Required<O>`）は元の宣言で判定する。
    if (narrowed.has(symbol) && signatures.every((d) => d.questionToken === undefined)) return true;
    if (!reached) return false;
    return viaAssertion
      ? signatures.some(
          (d) => d.type !== undefined && includesUndefined(checker.getTypeFromTypeNode(d.type)),
        )
      : includesUndefined(checker.getTypeOfSymbol(symbol));
  };

  for (const sf of scanned) {
    const record = (node: TS.Node, expression: string): void => {
      found.push({
        file: sf.fileName.slice(root.length + 1),
        line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1,
        expression,
      });
    };
    /** `o[k]` のキー候補。定数キーならそれ、`k: keyof O` のようなリテラルユニオンなら全メンバ。 */
    const keyCandidates = (
      node: TS.PropertyAccessExpression | TS.ElementAccessExpression,
    ): readonly string[] => {
      const constant = constantKey(ts, node);
      if (constant !== undefined) return [constant];
      if (!ts.isElementAccessExpression(node)) return [];
      const keyType = checker.getTypeAtLocation(node.argumentExpression);
      const members = keyType.isUnion() ? keyType.types : [keyType];
      return members.every((m) => m.isStringLiteral())
        ? members.map((m) => (m as TS.StringLiteralType).value)
        : [];
    };
    const visitMember = (node: TS.PropertyAccessExpression | TS.ElementAccessExpression): void => {
      if (legacy && !isParameterRooted(node.expression)) return;
      const bag = rootName(node.expression);
      const isWrite =
        ts.isBinaryExpression(node.parent) &&
        node.parent.left === node &&
        node.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken;
      if (isWrite) return;
      const receiver = node.expression.getText();
      const receiverType = checker.getTypeAtLocation(node.expression);
      const viaAssertion = isTypeAssertion(ts, node.expression);
      for (const key of keyCandidates(node)) {
        const symbol =
          ts.isPropertyAccessExpression(node) && key === node.name.text
            ? checker.getSymbolAtLocation(node.name)
            : checker.getNonNullableType(receiverType).getProperty(key);
        if (symbol === undefined || !isInheritableRead(symbol, bag, viaAssertion)) continue;
        if (!isGuardedByHasOwn(ts, node, receiver, key)) {
          record(node, `${receiver}.${key}`);
        }
      }
    };
    const visitPattern = (pattern: TS.ObjectBindingPattern): void => {
      // `catch ({ message })` のような例外の分割代入は外部入力ではない。
      if (pattern.parent.parent?.kind === ts.SyntaxKind.CatchClause) return;
      const initializer = ts.isVariableDeclaration(pattern.parent)
        ? pattern.parent.initializer
        : undefined;
      if (legacy) {
        const rooted =
          ts.isParameter(pattern.parent) ||
          (initializer !== undefined && isParameterRooted(initializer));
        if (!rooted) return;
      }
      const bag = initializer === undefined ? '{}' : rootName(initializer);
      const label =
        initializer?.getText() ?? checker.typeToString(checker.getTypeAtLocation(pattern));
      const source = checker.getNonNullableType(checker.getTypeAtLocation(pattern));
      for (const element of pattern.elements) {
        if (element.dotDotDotToken !== undefined) continue;
        // `const { controller: _dropped, ...rest } = doc` の `_` 始まりの束縛は、値を使わずに捨てるための取り除き。
        if (ts.isIdentifier(element.name) && element.name.text.startsWith('_')) continue;
        const key = element.propertyName ?? element.name;
        if (!ts.isIdentifier(key) && !ts.isStringLiteralLike(key)) continue;
        // 分割代入の識別子は局所変数に解決されるため、元の型からプロパティを引く。
        const property = source.getProperty(key.text);
        if (property !== undefined && isInheritableRead(property, bag, false)) {
          record(element, `{ ${key.text} } = ${label}`);
        }
      }
    };
    const visit = (node: TS.Node): void => {
      if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
        visitMember(node);
      }
      if (ts.isObjectBindingPattern(node)) visitPattern(node);
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return found;
}
