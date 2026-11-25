/**
 * PEx `field.path` のフィルタ / スクリプト式 `[?( …)]` `[( …)]` の評価器。
 *
 * `jsonpath-plus` の `eval: 'safe'`（`SafeScript`）は native eval を使わ
 * ないが、式内の**メソッド呼び出し**は実行する（`@.padStart(500000000,'x').indexOf('z')` が 3 KB の PD で
 * 30 秒停止し、`.split('')` は V8 を致命的 OOM で落とす）。`path-budget.ts` の予算はプロパティ読み出し回数 ×
 * 式の長さしか数えず、引数で巨大な文字列 / 配列を作る呼び出しの演算コストは計上されない。
 *
 * PEx が必要とする式は `@.a == 'x'` / `@.n >= 1 && @.t != 'y'` / `@.length > 0` 程度の「読み出しと比較」だけなので、
 * `SafeScript` を継承して構文木を**許可リスト**（読み出し・リテラル・比較・論理・算術・条件のみ）で検査し、
 * 呼び出し（`CallExpression`）・配列リテラル（`[@.a,@.a,…]` は比較・算術で `Array#join` による暗黙の文字列化を
 * 起こす）・代入など許可外のノードを含む式は評価前に拒否する（拒否は `resolveJsonPath` が「解決できなかった」に倒す）。
 *
 * 許可したノードも `SafeEval` では評価しない。演算子のオペランドが配列・オブジェクトだと `ToPrimitive` で文字列が
 * 確保され、長い文字列の比較・数値化は文字列長に比例して遅い。評価は `guarded-eval.ts` の自前の評価器で行い、
 * オペランドがプリミティブであること・文字列の走査量を予算へ前払いすることを実行時に保証する。
 */

import { JSONPath } from 'jsonpath-plus';
import { DisallowedPathExpressionError, evaluateGuardedAst } from './guarded-eval.js';

/** フィルタ式で許す構文木ノード種別（jsep）。`CallExpression` / `AssignmentExpression` 等は含めない。 */
const ALLOWED_NODE_TYPES: ReadonlySet<string> = new Set([
  'Literal',
  'Identifier',
  'MemberExpression',
  'BinaryExpression',
  'UnaryExpression',
  'ConditionalExpression',
  'Compound',
]);

/** jsep の構文木ノードのうち、検査で読むメンバ（型は実行時に確認する）。 */
interface AstNode {
  readonly type?: unknown;
}

/**
 * 構文木の全ノードが許可リストに含まれることを検査する。式長は構造検証で 512 以下のため再帰深さも有限。
 *
 * 許可したノードのオペランドの型（配列・オブジェクトの暗黙変換）は構文木からは決まらないため、評価時に
 * `guarded-eval.ts` が保証する。
 */
function assertAllowedAst(node: unknown): void {
  if (Array.isArray(node)) {
    for (const child of node) assertAllowedAst(child);
    return;
  }
  if (typeof node !== 'object' || node === null) return;
  const ast: AstNode = node;
  const type = ast.type;
  if (typeof type !== 'string' || !ALLOWED_NODE_TYPES.has(type)) {
    throw new DisallowedPathExpressionError();
  }
  for (const child of Object.values(node)) {
    if (typeof child === 'object' && child !== null) assertAllowedAst(child);
  }
}

/** `jsonpath-plus` が `eval` に受け取る式クラス（`new Script(code).runInNewContext(context)`）。 */
interface PathScript {
  new (code: string): { runInNewContext(context: object): unknown };
}

function isPathScript(value: unknown): value is PathScript {
  return typeof value === 'function';
}

/**
 * `jsonpath-plus` はスクリプト式 `[(expr)]` を括弧ごと（`(expr)`）、フィルタ式 `[?(expr)]` を中身（`expr`）だけ渡す。
 * 括弧で始まり括弧で終わるフィルタ式（`[?((@.a==1))]` 等）もスクリプト式とみなすが、その場合はオペランド違反で
 * path 全体を中断する従来の挙動（fail-closed）になるだけで、一致を広げる方向には働かない。
 */
function isScriptExpressionCode(code: string): boolean {
  return code.startsWith('(') && code.endsWith(')');
}

let cached: PathScript | undefined;

/**
 * 許可リスト検査つきの式クラスを返す（初回に 1 度だけ作る）。
 *
 * `JSONPath.prototype.safeVm.Script`（jsonpath-plus の `SafeScript`）を継承するため、モジュール読み込み時ではなく
 * 初回評価時に解決する（extension の PEx スタブ `JSONPath` は評価されず、読み込み時に参照すると失敗する）。
 * `SafeScript` が見つからない・構文木を持たない場合は式を評価せず例外にする（fail-closed。jsonpath-plus
 * の更新で前提が崩れたときに検査なしの評価へ黙って退化させない）。
 */
export function guardedPathScript(): PathScript {
  if (cached !== undefined) return cached;
  const proto: object = JSONPath.prototype;
  const safeVm = 'safeVm' in proto ? proto.safeVm : undefined;
  const Base: unknown =
    typeof safeVm === 'object' && safeVm !== null && 'Script' in safeVm ? safeVm.Script : undefined;
  if (!isPathScript(Base)) {
    throw new DisallowedPathExpressionError();
  }
  // `jsonpath-plus` は `eval` クラスの prototype が `runInNewContext` を**自前で**持つかで式クラスか関数かを
  // 判別するため、継承せずに明示的に定義する。
  class GuardedScript extends Base {
    readonly #checkedAst: unknown;
    readonly #isFilter: boolean;

    constructor(code: string) {
      super(code);
      const ast: unknown = 'ast' in this ? this.ast : undefined;
      if (typeof ast !== 'object' || ast === null) {
        throw new DisallowedPathExpressionError();
      }
      assertAllowedAst(ast);
      this.#checkedAst = ast;
      this.#isFilter = !isScriptExpressionCode(code);
    }

    override runInNewContext(context: object): unknown {
      return evaluateGuardedAst(this.#checkedAst, context, this.#isFilter);
    }
  }
  cached = GuardedScript;
  return cached;
}
