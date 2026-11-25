/**
 * PEx `field.path`（JSONPath）の評価量予算。
 *
 * `path` は Verifier 由来の非信頼入力で、`jsonpath-plus` は
 * 走査ノード数を制限しない。構文的に正しい `$..*..*..*..*` や `$[0,0,0,0][0,0,0,0]…` は評価量が
 * 入れ子の深さ・path 長に対して多項式 / 指数的に増え、同期処理を分単位で占有できる。
 *
 * `jsonpath-plus` に走査の途中経過を知らせる口は無いため、クレームを読み取り専用の `Proxy` で包み、
 * プロパティの読み出し（`get` / `has` / `ownKeys` / `getOwnPropertyDescriptor`）を数えて予算を
 * 使い切ったら例外で打ち切る。評価は常にこのビューを経由するため、`jsonpath-plus` の内部実装に
 * 依存せずに走査量を数えられる。
 *
 * フィルタ式 `[?( … )]` / スクリプト式 `[( … )]` は要素ごとに式を評価するが、その演算コストは読み出し
 * 回数に現れない（200 項の式 × 1,000 要素の配列が読み出し 1 回あたり約 200 演算で数十秒かかる）。
 * そこで式を含む path では 1 回の読み出しに**式の長さ**を掛けて計上する（{@link expressionWeight}）。
 *
 * `jsonpath-plus` の `_trace` はノードごとに親の path 配列をコピーして 1 要素足し（`push(path, m)`）、
 * `$..*` は一致した全ノードの path 配列を結果に保持するため、深さ D・ノード数 N のクレームで確保量は
 * 読み出し回数 O(N) のまま O(N×D) になる。そこで読み出しには、読む対象の**深さ**も加算して計上する
 * （深さ D のノードを 1 回読むと `cost + D`。確保される path 配列の長さに相当）。
 */

import { consumeWork, type WorkBudget } from '../primitives/work-budget.js';

/** 1 回の `evaluatePresentationDefinition` で JSONPath 評価に使ってよいプロパティ読み出しの総数。 */
export const MAX_PATH_READS = 2_000_000;

/**
 * `JSONPath()` 1 回の呼び出しの固定費（読み出し換算）。`$^` / `$~` / `$` / `@` のように読み出しが
 * 1 回も起きない path でも、インスタンス生成・`budgetedView` の Proxy 生成・結果配列の確保が毎回かかる
 * （実測で 1 回あたり数 µs）。`MAX_PATH_READS` に対して総呼び出しを 12.5 万回で頭打ちにする。
 * 計上は `resolveJsonPath`（評価の最小単位）が入口で行う。
 */
export const PATH_CALL_COST = 16;

/**
 * `Field` 1 件の評価の固定費（読み出し換算）。`optional` で path が解決できない・`filter` が無い
 * フィールドを記述子 × フィールド × 保有 VC の積だけ評価させても予算が減らない状態をなくす。
 * 計上は `evaluateField`（評価の最小単位）が入口で行う。
 */
export const FIELD_EVALUATION_COST = 4;

/** JSONPath 評価の共有予算（総量は {@link MAX_PATH_READS}）。残量・枯渇フラグは共通の {@link WorkBudget}。 */
export type PathBudget = WorkBudget;

/** 予算超過で評価を打ち切る内部例外（`resolveJsonPath` が握る。メッセージにクレーム値を含めない）。 */
export class PathBudgetExceededError extends Error {
  constructor() {
    super('JSONPath evaluation budget exceeded');
    this.name = 'PathBudgetExceededError';
  }
}

/**
 * path の式（最初の `(` 以降）の長さ。式を含まない path は 0。
 *
 * AST ノード数は式の文字数以下なので、文字数は 1 要素あたりの評価演算数の上界になる。
 * path 長は構造検証で 512 以下に制限済みのため、1 回の読み出しの重みも有限。
 */
export function expressionWeight(path: string): number {
  const start = path.indexOf('(');
  return start === -1 ? 0 : path.length - start;
}

function charge(budget: PathBudget, units: number): void {
  if (!consumeWork(budget, units)) {
    throw new PathBudgetExceededError();
  }
}

/**
 * クレームの読み取りを予算へ計上するビューを返す。
 *
 * `Proxy` の対象は実物ではなく空の「影」（配列か object）にする。クレームが凍結されている場合に
 * 子ビューを返す `get` が不変条件違反（`TypeError`）になるのを避けるため。書き込み系の操作は
 * 影にだけ作用し、実物へは届かない。
 */
export function budgetedView<T extends object>(claims: T, budget: PathBudget, weight = 0): T {
  const cost = 1 + weight;
  /** 深さ → (実物 → ビュー)。同じ実物でも辿った深さが違えば別ビュー（別名参照で深さを過小に数えさせない）。 */
  const viewsByDepth: WeakMap<object, object>[] = [];

  const view = (real: object, depth: number): object => {
    const views = viewsByDepth[depth] ?? new WeakMap<object, object>();
    viewsByDepth[depth] = views;
    const existing = views.get(real);
    if (existing !== undefined) {
      return existing;
    }
    const created = new Proxy(Array.isArray(real) ? [] : {}, {
      get(_shadow, key) {
        charge(budget, cost + depth);
        const value: unknown = Reflect.get(real, key);
        return typeof value === 'object' && value !== null ? view(value, depth + 1) : value;
      },
      has(_shadow, key) {
        charge(budget, cost + depth);
        return Reflect.has(real, key);
      },
      ownKeys() {
        const keys = Reflect.ownKeys(real);
        charge(budget, 1 + keys.length + depth);
        return keys;
      },
      getOwnPropertyDescriptor(_shadow, key) {
        charge(budget, cost + depth);
        const descriptor = Reflect.getOwnPropertyDescriptor(real, key);
        if (descriptor === undefined) {
          return undefined;
        }
        // 影に存在しないプロパティを非 configurable として報告すると Proxy の不変条件に反する
        // （配列の `length` だけは影も非 configurable のため値だけ合わせる）。
        const value: unknown = descriptor.value;
        const reported =
          typeof value === 'object' && value !== null
            ? { ...descriptor, value: view(value, depth + 1) }
            : descriptor;
        return key === 'length' && Array.isArray(real)
          ? { ...reported, writable: true, configurable: false }
          : { ...reported, configurable: true };
      },
    });
    views.set(real, created);
    return created;
  };

  return view(claims, 0) as T;
}
