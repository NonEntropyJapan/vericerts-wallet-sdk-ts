/**
 * フォーマットネゴシエーションの仕事量予算。
 *
 * `vp_formats`（`client_metadata` 由来で非信頼）の制約配列長 A × フォーマット数 K × 記述子数 D × 候補 VC 数 C は
 * いずれも個別の上限が無く、小さなリクエストで同期処理を数十秒占有できた。評価の最小単位
 * （制約 1 件の判定・スコア 1 件の計算・比較 1 回・候補 1 件の走査）が自分の入口で
 * {@link chargeFormatWork} を呼び、1 回の `evaluateFormatCapability` 全体で 1 つの予算を共有する。
 * 最小単位の関数は予算を必須引数で受け取るので、計上漏れが型で検出される。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { consumeWork, createWorkBudget, type WorkBudget } from '../../primitives/work-budget.js';

/**
 * 1 回の `evaluateFormatCapability` / `selectBestVC` / `canFulfillFormats` が使ってよい仕事量の総量。
 * 単位は配列要素・候補・比較 1 回。1 単位は数 ns で、上限に達するまで約 25 ms 程度。
 * 実在の `vp_formats`（フォーマット数個 × 制約配列数個）× 記述子数十件 × 保有 VC 数千件に十分な値。
 */
export const MAX_FORMAT_WORK_UNITS = 5_000_000;

/** 予算超過を表す `context.reason`。 */
export const FORMAT_WORK_EXCEEDED_REASON = 'format_work_budget_exceeded';

/** 新しい仕事量予算を作る。 */
export function createFormatWorkBudget(): WorkBudget {
  return createWorkBudget(MAX_FORMAT_WORK_UNITS);
}

/**
 * `units` を計上する。予算が尽きたら 3050（`VP_FORMATS_NOT_SUPPORTED`、`reason: 'format_work_budget_exceeded'`）を投げる
 * （fail-closed。以降の呼び出しも即座に同じ例外になる）。
 */
export function chargeFormatWork(budget: WorkBudget, units: number): void {
  if (!consumeWork(budget, units)) {
    throw new VericertsError(ErrorCodes.VP_FORMATS_NOT_SUPPORTED, {
      context: { reason: FORMAT_WORK_EXCEEDED_REASON },
    });
  }
}
