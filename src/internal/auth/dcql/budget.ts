/**
 * DCQL 評価の仕事量予算（共通計数器を DCQL に適用）。
 *
 * 要件 R 件 × 保有 VC H 件 × `claims` 件数 × `path` 長 × `values` 件数は、パース時の個別上限を
 * 守った query でも保有 VC 数 H に比例して増える。評価の最小単位（要件 1 件 × VC 1 件の突き合わせ、
 * claim 1 件の path 解決、`values` / `vct_values` の走査）が自分の入口で {@link chargeDcqlWork} を呼び、
 * 1 回の評価（Presentation Request 1 件）で 1 つの予算を共有する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { consumeWork, createWorkBudget, type WorkBudget } from '../../primitives/work-budget.js';

/**
 * 1 回の DCQL 評価（`evaluateDcql` / `findMatchingCredentialIndexes`）が使ってよい仕事量の総量。
 * 単位は要件 × VC の組・`path` の 1 キー・`values` / `vct_values` の 1 要素。実在の query（要件数個 ×
 * claim 数個）と保有 VC 数千件に十分で、悪意ある query が使える同期処理を数十 ms に抑える値。
 */
export const MAX_DCQL_WORK_UNITS = 20_000_000;

/** 仕事量予算超過を表す `context.reason`。 */
export const DCQL_WORK_EXCEEDED_REASON = 'dcql_work_budget_exceeded';

/** 新しい DCQL 仕事量予算を作る。 */
export function createDcqlWorkBudget(): WorkBudget {
  return createWorkBudget(MAX_DCQL_WORK_UNITS);
}

/** `units` を計上する。予算が尽きたら 8030（`dcql_work_budget_exceeded`。fail-closed）。 */
export function chargeDcqlWork(budget: WorkBudget, units: number): void {
  if (!consumeWork(budget, units)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: DCQL_WORK_EXCEEDED_REASON },
    });
  }
}
