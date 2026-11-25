/**
 * PEx フィルタ式 `[?( …)]` の評価器（`guarded-script.ts` の許可リスト検査を通った構文木だけを評価する）。
 *
 * `jsonpath-plus` の `SafeEval` は JS の演算子をそのまま適用する。オペランドが配列・オブジェクトだと
 * `ToPrimitive`（`Array#join` / `toString`）が走り、文字列が式の外で確保される（`[@.a,@.a,…]<'a'` は 1 評価で
 * オペランド長 × 要素数の確保。1 MB の文字列 1 本 × 8 フィールドの 4.4 KB の PD で RSS 864 MB）。文字列同士の
 * 比較・数値化（`'1…1'*1`）も文字列長に比例する演算で、読み出し予算には現れない。「`+` の拒否」はこの
 * うち `+` というトークンしか塞いでいなかった。
 *
 * そこで構文木の検査（どのノードを許すか）とは別に、評価時に**オペランドの型を保証**する自前の評価器で評価する。
 * - 比較・算術・ビット・シフト・単項 `+ - ~` のオペランドはプリミティブ（文字列・数値・真偽・null・undefined）に
 *   限る。配列・オブジェクト・関数・RegExp は暗黙の型変換（`ToPrimitive`）を起こすため例外にする。
 * - 文字列を数値へ暗黙変換する演算（`'1'*1` / `@.s<1` / `@.s==1`）は、文字列が短いとき（{@link MAX_COERCED_STRING_LENGTH}）
 *   だけ許す（長い数字列の変換は文字列長に対して非線形に遅い）。`+` は文字列を連結しうるため文字列オペランドを拒否する。
 * - 文字列同士の比較（`< > <= >= == != === !==`）と、文字列をプロパティキーにする計算メンバーは、比較・探索で走査する
 *   文字数を {@link consumeWork} で**演算の前に**予算へ前払いする（超過は {@link PathBudgetExceededError}）。
 * - メンバーアクセスは関数値・`constructor` / `__proto__` 等を返さない。
 * 例外はすべて `jsonpath-plus` が素の Error に包んで投げ、`resolveJsonPath` が「解決できなかった」に倒す。
 * ただしフィルタ式でオペランドの型・長さ（クレーム値に依存する違反。{@link DisallowedOperandError}）だけが原因なら、
 * その要素だけを不一致にする（`jsonpath-plus` は例外を要素単位で握らず path 全体を中断するため、無関係な
 * 1 要素のせいで一致していた要素まで消える）。否定（`!`）等で一致へ転じないよう、式全体を偽として扱う。
 */

import { consumeWork, type WorkBudget } from '../primitives/work-budget.js';
import { PathBudgetExceededError } from './path-budget.js';

/** 式の構文木に許可外ノード・許可外のオペランドが含まれる場合の内部例外（メッセージに式・クレーム値を含めない）。 */
export class DisallowedPathExpressionError extends Error {
  constructor() {
    super('JSONPath expression contains a disallowed construct');
    this.name = 'DisallowedPathExpressionError';
  }
}

/**
 * オペランドの型・長さがクレーム値に依存して許可外だった場合の内部例外。構文木の許可リスト違反とは区別し、
 * フィルタ式ではその要素だけを不一致にする。
 */
export class DisallowedOperandError extends Error {
  constructor() {
    super('JSONPath expression operand is not allowed');
    this.name = 'DisallowedOperandError';
  }
}

/** 評価コンテキスト（sandbox）に予算を渡すキー。式の識別子（文字列キー）からは到達できない。 */
export const EXPRESSION_BUDGET_KEY: unique symbol = Symbol('pex.expressionBudget');

/** 文字列を数値へ暗黙変換してよい最大長（式の長さの上限 512 の範囲。これを超える文字列は数値演算に使えない）。 */
export const MAX_COERCED_STRING_LENGTH = 64;

/**
 * `constructor` 等、プロトタイプ経由で到達できる危険なプロパティ（`jsonpath-plus` の `SafeEval` と同じ集合）。
 * `__proto__` をキーにしたオブジェクトリテラルは own プロパティにならないため `Set` で持つ。
 */
const BLOCKED_PROTO_PROPERTIES: ReadonlySet<string> = new Set([
  'constructor',
  '__proto__',
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
]);

type Primitive = string | number | boolean | null | undefined;

interface Scope {
  readonly vars: Readonly<Record<string, unknown>>;
  readonly budget: WorkBudget;
}

function assertPrimitive(value: unknown): Primitive {
  if (
    value === null ||
    value === undefined ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return value;
  }
  throw new DisallowedOperandError();
}

/** 文字列の走査量を評価の前に予算へ前払いする。予算が足りなければ例外（`resolveJsonPath` が不一致に倒す）。 */
function prepay(scope: Scope, units: number): void {
  if (!consumeWork(scope.budget, units)) throw new PathBudgetExceededError();
}

/** 数値演算のオペランド（`ToNumber` 相当）。文字列は短いものだけ数値へ変換してよい（長さを前払いする）。 */
function numericOperand(scope: Scope, value: unknown): number {
  const primitive = assertPrimitive(value);
  if (typeof primitive === 'string') {
    if (primitive.length > MAX_COERCED_STRING_LENGTH) throw new DisallowedOperandError();
    prepay(scope, primitive.length);
  }
  return Number(primitive);
}

/** 比較演算子。両辺は文字列同士か、数値へ変換できるプリミティブに限る。 */
function compare(scope: Scope, operator: string, left: unknown, right: unknown): boolean {
  const a = assertPrimitive(left);
  const b = assertPrimitive(right);
  if (typeof a === 'string' && typeof b === 'string') {
    prepay(scope, Math.min(a.length, b.length));
    return compareValues(operator, a, b);
  }
  // `null` / `undefined` との `==` / `!=` は型変換が起きないので、そのまま比べる。
  if (operator === '==' || operator === '!=') {
    if (a === null || a === undefined || b === null || b === undefined) {
      return compareValues(operator, a, b);
    }
  }
  return compareValues(operator, numericOperand(scope, a), numericOperand(scope, b));
}

function compareValues(operator: string, a: unknown, b: unknown): boolean {
  switch (operator) {
    case '==':
      // biome-ignore lint/suspicious/noDoubleEquals: PEx のフィルタ式は JS の `==`（プリミティブ同士の緩い等価）の意味で書かれる
      return a == b;
    case '!=':
      // biome-ignore lint/suspicious/noDoubleEquals: 同上（`!=`）
      return a != b;
    case '<':
      return (a as number) < (b as number);
    case '>':
      return (a as number) > (b as number);
    case '<=':
      return (a as number) <= (b as number);
    default:
      return (a as number) >= (b as number);
  }
}

function arithmetic(operator: string, a: number, b: number): number {
  switch (operator) {
    case '+':
      return a + b;
    case '-':
      return a - b;
    case '*':
      return a * b;
    case '/':
      return a / b;
    case '%':
      return a % b;
    case '|':
      return a | b;
    case '^':
      return a ^ b;
    case '&':
      return a & b;
    case '<<':
      return a << b;
    case '>>':
      return a >> b;
    case '>>>':
      return a >>> b;
    default:
      throw new DisallowedPathExpressionError();
  }
}

function binary(scope: Scope, operator: string, left: unknown, right: unknown): unknown {
  switch (operator) {
    case '===':
    case '!==':
      // 型変換は起きないが、同じ長さの文字列は先頭から走査する。
      if (typeof left === 'string' && typeof right === 'string') {
        prepay(scope, Math.min(left.length, right.length));
      }
      return operator === '===' ? left === right : left !== right;
    case '==':
    case '!=':
    case '<':
    case '>':
    case '<=':
    case '>=':
      return compare(scope, operator, left, right);
    case '+':
      // 文字列は連結になる（結果の確保が予算に載らない）ため、数値系のオペランドに限る。
      if (typeof left === 'string' || typeof right === 'string') {
        throw new DisallowedOperandError();
      }
      return arithmetic(operator, numericOperand(scope, left), numericOperand(scope, right));
    default:
      return arithmetic(operator, numericOperand(scope, left), numericOperand(scope, right));
  }
}

function unary(scope: Scope, operator: string, argument: unknown): unknown {
  switch (operator) {
    case '!':
      return !argument;
    case 'typeof':
      return typeof argument;
    case 'void':
      return undefined;
    case '-':
      return -numericOperand(scope, argument);
    case '+':
      return numericOperand(scope, argument);
    case '~':
      return ~numericOperand(scope, argument);
    default:
      throw new DisallowedPathExpressionError();
  }
}

function member(scope: Scope, object: unknown, key: unknown): unknown {
  if (object === undefined || object === null) throw new TypeError('Cannot read properties');
  // キーは文字列 / 数値だけ（配列・オブジェクトを `String()` で文字列化させない）。長い文字列キーの探索量は前払いする。
  if (typeof key !== 'string' && typeof key !== 'number') throw new DisallowedOperandError();
  const property = String(key);
  if (typeof key === 'string') prepay(scope, key.length);
  const target = object as Record<string, unknown>;
  if (!Object.hasOwn(target, property) && BLOCKED_PROTO_PROPERTIES.has(property)) {
    throw new TypeError('Cannot read properties');
  }
  const result = target[property];
  // メソッドは呼べない（呼び出しは許可リストで拒否済み）が、比較で関数が文字列化されるのも避ける。
  if (typeof result === 'function') throw new DisallowedOperandError();
  return result;
}

interface Node {
  readonly type?: unknown;
  readonly operator?: unknown;
  readonly value?: unknown;
  readonly name?: unknown;
  readonly computed?: unknown;
  readonly argument?: unknown;
  readonly left?: unknown;
  readonly right?: unknown;
  readonly test?: unknown;
  readonly consequent?: unknown;
  readonly alternate?: unknown;
  readonly object?: unknown;
  readonly property?: unknown;
  readonly body?: unknown;
}

function asNode(value: unknown): Node {
  if (typeof value !== 'object' || value === null) throw new DisallowedPathExpressionError();
  return value;
}

function evalNode(scope: Scope, raw: unknown): unknown {
  const node = asNode(raw);
  switch (node.type) {
    case 'Literal':
      return node.value;
    case 'Identifier': {
      if (typeof node.name === 'string' && Object.hasOwn(scope.vars, node.name)) {
        return scope.vars[node.name];
      }
      throw new ReferenceError('identifier is not defined');
    }
    case 'MemberExpression': {
      const key =
        node.computed === true ? evalNode(scope, node.property) : asNode(node.property).name;
      return member(scope, evalNode(scope, node.object), key);
    }
    case 'UnaryExpression': {
      if (typeof node.operator !== 'string') throw new DisallowedPathExpressionError();
      return unary(scope, node.operator, evalNode(scope, node.argument));
    }
    case 'BinaryExpression':
    case 'LogicalExpression': {
      const operator = node.operator;
      if (typeof operator !== 'string') throw new DisallowedPathExpressionError();
      const left = evalNode(scope, node.left);
      // `&&` / `||` は短絡評価する（右辺の読み出しを予算に載せない）。
      if (operator === '&&') return left && evalNode(scope, node.right);
      if (operator === '||') return left || evalNode(scope, node.right);
      return binary(scope, operator, left, evalNode(scope, node.right));
    }
    case 'ConditionalExpression':
      return evalNode(scope, evalNode(scope, node.test) ? node.consequent : node.alternate);
    case 'Compound': {
      if (!Array.isArray(node.body)) throw new DisallowedPathExpressionError();
      let last: unknown;
      for (const expression of node.body) last = evalNode(scope, expression);
      return last;
    }
    default:
      throw new DisallowedPathExpressionError();
  }
}

/**
 * `JSONPath({ sandbox })` に渡す評価コンテキストを作る。型定義は `Map` だが、実体は `Object.assign` で
 * 自身の列挙可能プロパティ（`_$_v` 等と {@link EXPRESSION_BUDGET_KEY}）だけが式の変数へ複製される。
 */
export function expressionSandbox(budget: WorkBudget): Map<string, unknown> {
  return Object.assign(new Map<string, unknown>(), { [EXPRESSION_BUDGET_KEY]: budget });
}

/**
 * 許可リスト検査済みの構文木 `ast` を評価する。`context` は `jsonpath-plus` の sandbox（`_$_v` 等）で、
 * {@link EXPRESSION_BUDGET_KEY} に評価予算を持つ（無ければ評価しない）。
 *
 * `isFilter` が真（フィルタ式 `[?( …)]`）のとき、{@link DisallowedOperandError} はその要素の不一致（`false`）にする。
 * スクリプト式 `[( … )]` は結果がプロパティ名になる（偽値に倒すとキー `false` を読む）ため、従来どおり例外にする。
 * 予算超過（{@link PathBudgetExceededError}）と構文木の違反は、いずれの式でも path 全体を中断する。
 */
export function evaluateGuardedAst(ast: unknown, context: object, isFilter: boolean): unknown {
  const budget: unknown = (context as Record<symbol, unknown>)[EXPRESSION_BUDGET_KEY];
  if (typeof budget !== 'object' || budget === null || !('remaining' in budget)) {
    throw new DisallowedPathExpressionError();
  }
  const vars: Record<string, unknown> = Object.assign(Object.create(null), context);
  try {
    return evalNode({ vars, budget: budget as WorkBudget }, ast);
  } catch (error) {
    if (isFilter && error instanceof DisallowedOperandError) return false;
    throw error;
  }
}
