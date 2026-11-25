/**
 * 「外部入力由来の型」のメンバを集める（scan.ts の規則 4b / 4c）。
 *
 * 外部入力の起点は 2 つ。
 * - 公開 API の入口が export する関数・クラスのパラメータ型（呼び出し側が自由に渡す値）。
 * - `any` / `unknown` からの型の絞り込み（`JSON.parse(..) as T` / `await res.json() as T` / `const x: T = JSON.parse(..)` /
 *   `(x: unknown): x is T`）。ネットワーク応答・ストレージ・メッセージの形はここで型が付く。
 *
 * メンバは symbol ではなく**宣言ノード**で記録する。`Required<O>` / `Readonly<O>` の写しのプロパティ symbol は元の宣言を引き継ぐので、
 * 宣言で引くと `(o as Required<O>).a` のような型だけの付け替えでも元の外部入力型と分かる。
 */

import type * as TS from 'typescript';

/** `typescript` モジュール本体。呼び出し側（sdk / extension のテスト）が自パッケージの依存から渡す。 */
export type TypeScriptApi = typeof TS;

const MAX_TYPE_DEPTH = 12;

/** 型が `node_modules` / lib の宣言ではなく、このパッケージで宣言されたものか。 */
function isProjectDeclared(symbol: TS.Symbol): boolean {
  return (symbol.declarations ?? []).some((d) => {
    const file = d.getSourceFile();
    return !file.hasNoDefaultLib && !file.fileName.includes('/node_modules/');
  });
}

/** 外部入力由来の型のメンバ（プロパティ宣言）の集合。 */
export class ExternalProperties {
  readonly #declarations = new Set<TS.Node>();
  readonly #seen = new Set<TS.Type>();

  readonly #ts: TypeScriptApi;
  readonly #checker: TS.TypeChecker;
  /**
   * true なら関数型（コールバック・メソッド）の引数・戻り値を辿らない。JSON の絞り込み先の「データの形」だけを集めるとき用
   * （クラスのメソッドの戻り値は、このライブラリが own で組み立てる値であって外部入力ではない）。
   */
  readonly #dataOnly: boolean;

  constructor(ts: TypeScriptApi, checker: TS.TypeChecker, dataOnly = false) {
    this.#ts = ts;
    this.#checker = checker;
    this.#dataOnly = dataOnly;
  }

  /** `symbol`（`Required<O>` 等の写しを含む）が外部入力由来の型のメンバか。 */
  has(symbol: TS.Symbol): boolean {
    return (symbol.declarations ?? []).some((d) => this.#declarations.has(d));
  }

  /** `type` から、プロパティ・配列要素・ユニオン・型引数・コールバックの引数/戻り値を辿って到達できるメンバを加える。 */
  add(type: TS.Type, depth = 0): void {
    const ts = this.#ts;
    const checker = this.#checker;
    if (depth > MAX_TYPE_DEPTH || this.#seen.has(type)) return;
    this.#seen.add(type);
    if (type.isUnionOrIntersection()) {
      for (const member of type.types) this.add(member, depth + 1);
      return;
    }
    if ((type.flags & ts.TypeFlags.Object) === 0) return;
    const objectType = type as TS.ObjectType;
    if ((objectType.objectFlags & ts.ObjectFlags.Reference) !== 0) {
      for (const arg of checker.getTypeArguments(objectType as TS.TypeReference)) {
        this.add(arg, depth + 1);
      }
    }
    // コールバック引数（`(vc: NegotiableCredential) => boolean`）は、呼び出し側の関数へ渡す値なので外部入力の型ではないが、
    // 呼び出し側が返す値は入力になる。引数・戻り値の両方を辿る。
    if (this.#dataOnly && type.getCallSignatures().length > 0) return;
    for (const signature of type.getCallSignatures()) {
      for (const param of signature.getParameters()) {
        this.add(checker.getTypeOfSymbol(param), depth + 1);
      }
      this.add(signature.getReturnType(), depth + 1);
    }
    if (type.symbol === undefined || !isProjectDeclared(type.symbol)) return;
    for (const property of checker.getPropertiesOfType(type)) {
      for (const declaration of property.declarations ?? []) this.#declarations.add(declaration);
      this.add(checker.getTypeOfSymbol(property), depth + 1);
    }
    for (const info of checker.getIndexInfosOfType(type)) this.add(info.type, depth + 1);
  }

  /** 公開 API の入口が export する関数・クラス（コンストラクタとメソッド）のパラメータ型を起点に加える。 */
  addPublicEntries(entries: readonly TS.SourceFile[]): void {
    const ts = this.#ts;
    const checker = this.#checker;
    const addSignatures = (signatures: readonly TS.Signature[]): void => {
      for (const signature of signatures) {
        for (const param of signature.getParameters()) this.add(checker.getTypeOfSymbol(param));
      }
    };
    for (const entry of entries) {
      const moduleSymbol = checker.getSymbolAtLocation(entry);
      if (moduleSymbol === undefined) continue;
      for (const exported of checker.getExportsOfModule(moduleSymbol)) {
        const symbol =
          (exported.flags & ts.SymbolFlags.Alias) !== 0
            ? checker.getAliasedSymbol(exported)
            : exported;
        const valueType = checker.getTypeOfSymbolAtLocation(symbol, entry);
        addSignatures(valueType.getCallSignatures());
        if ((symbol.flags & ts.SymbolFlags.Class) === 0) continue;
        addSignatures(valueType.getConstructSignatures());
        for (const method of checker.getPropertiesOfType(checker.getDeclaredTypeOfSymbol(symbol))) {
          addSignatures(checker.getTypeOfSymbol(method).getCallSignatures());
        }
      }
    }
  }

  /** `any` / `unknown` から型を絞り込む箇所（型アサーション・型注釈付き変数・型述語）の絞り込み先を起点に加える。 */
  addNarrowingTargets(file: TS.SourceFile): void {
    const ts = this.#ts;
    const checker = this.#checker;
    const isUntyped = (type: TS.Type): boolean =>
      (type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) !== 0;
    const visit = (node: TS.Node): void => {
      if (
        (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) &&
        isUntyped(checker.getTypeAtLocation(node.expression))
      ) {
        this.add(checker.getTypeAtLocation(node));
      } else if (
        ts.isVariableDeclaration(node) &&
        node.type !== undefined &&
        node.initializer !== undefined &&
        isUntyped(checker.getTypeAtLocation(node.initializer))
      ) {
        this.add(checker.getTypeFromTypeNode(node.type));
      } else if (
        ts.isTypePredicateNode(node) &&
        node.type !== undefined &&
        ts.isIdentifier(node.parameterName)
      ) {
        const parameter = checker.getSymbolAtLocation(node.parameterName)?.valueDeclaration;
        if (parameter !== undefined && isUntyped(checker.getTypeAtLocation(parameter))) {
          this.add(checker.getTypeFromTypeNode(node.type));
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
}
