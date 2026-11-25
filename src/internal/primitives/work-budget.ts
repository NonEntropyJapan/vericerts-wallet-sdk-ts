/**
 * 評価の仕事量予算（共通の計数器）。
 *
 * Verifier 由来の非信頼入力（PEx の `field` / `path` / `enum`、DCQL の `claims` / `path` / `values`、
 * `vp_formats` の制約配列）を保持 VC / 記述子の件数ぶん繰り返し評価する経路は、入力サイズに個別の上限を
 * 足すだけでは何度も迂回された。
 * 総回数・総量を 1 つの予算に数えさせ、超過は fail-closed にする。
 *
 * **計上は評価の最小単位（1 フィールド / 1 path / 1 enum 要素 / 1 制約要素）の関数が自分で行う。**
 * 呼び出し側が「押し忘れる」ことがないよう、最小単位の評価関数は予算を**必須引数**で受け取り、
 * 自身の入口で {@link consumeWork} を呼ぶ。上限の超過時の振る舞い（不一致 / 例外）は各評価経路が決める。
 */

/** 残量を持つ予算。使い切ると `exhausted` が立ち、以降の {@link consumeWork} は常に `false`。 */
export interface WorkBudget {
  /** 残りの単位数。 */
  remaining: number;
  /** 一度でも上限を超えたか（以降は不可逆）。 */
  exhausted: boolean;
}

/** 総量 `limit` の新しい予算を作る。 */
export function createWorkBudget(limit: number): WorkBudget {
  return { remaining: limit, exhausted: false };
}

/**
 * `units` を消費する。
 * @returns 残量が足りれば `true`。足りなければ（`units` が NaN・負でも）残量を 0 にして `exhausted` を立て、`false`。
 *   `units` に配列長などの未検証の値を渡してもすり抜けない（`undefined` → NaN は枯渇扱い）。
 */
export function consumeWork(budget: WorkBudget, units: number): boolean {
  if (budget.exhausted || !(units >= 0 && units <= budget.remaining)) {
    budget.remaining = 0;
    budget.exhausted = true;
    return false;
  }
  budget.remaining -= units;
  return true;
}
