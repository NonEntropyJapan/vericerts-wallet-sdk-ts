/**
 * 署名スイート制約の充足判定。
 *
 * `select.ts` / `coverage.ts` の両方から使う共通ロジックを切り出す
 * （`Linterly` の行数上限対応でのファイル分割。責務・公開 API に変更はない）。
 */

import type { WorkBudget } from '../../primitives/work-budget.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  formatConstraintOf,
  type NegotiableCredential,
  type VpFormatRequirement,
} from './types.js';
import { chargeFormatWork } from './work.js';

/**
 * 単一の署名スイート制約（`alg` / `proof_type` / `cryptosuite` / `-zkp_suite` のいずれか）を
 * VC の実値が満たすか。
 *
 * 制約が未指定または空配列 → 中立（満たす扱い）。制約があり VC 側の値が `undefined` または
 * 集合外 → 不適合（強度降格の拒否）。
 *
 * `allowed` は Verifier 由来の生 JSON（`client_metadata.vp_formats`）で型が保証されない。
 * 文字列だと `includes` が部分一致（`'ES256K'.includes('ES256')`）で制約をすり抜け、数値・オブジェクト
 * では `TypeError` になるため、文字列配列以外は不適合（fail-closed）。
 */
function satisfiesSuiteConstraint(
  allowed: unknown,
  actual: string | undefined,
  budget: WorkBudget,
): boolean {
  if (allowed === undefined) {
    return true;
  }
  if (!Array.isArray(allowed)) {
    return false;
  }
  // 型検査（`every`）と集合内判定（`includes`）で配列を 2 回走査する。要素数ぶんを走査の前に計上する
  // （制約配列長 A × 候補数 C × 記述子数 D の積を予算で縛る）。
  chargeFormatWork(budget, 2 * allowed.length);
  if (!allowed.every((value) => typeof value === 'string')) {
    return false;
  }
  if (allowed.length === 0) {
    return true;
  }
  return actual !== undefined && allowed.includes(actual);
}

/**
 * 候補 VC が Verifier の要求フォーマット + 署名スイート制約を満たすか。
 *
 * - フォーマットが要求集合に含まれない、または制約がオブジェクトでない（`null` / `true` / 文字列 /
 *   配列）→ 除外
 * - 要求制約に `alg` / `proof_type`（Data Integrity）/ `cryptosuite`（Data Integrity v2）/
 *   `-zkp_suite`（BBS+）があり、VC の対応する実値がその集合外、または制約値が文字列配列でない
 *   → 除外（強度降格の拒否）
 */
export function satisfiesRequirement(
  vc: NegotiableCredential,
  requested: VpFormatRequirement,
  budget: WorkBudget,
): boolean {
  // 候補 1 件 × 要求 1 件の判定は、制約が何件・どの形でも固定費 1 を計上する。
  chargeFormatWork(budget, 1);
  const constraint: unknown = formatConstraintOf(requested, vc.format);
  if (typeof constraint !== 'object' || constraint === null || Array.isArray(constraint)) {
    return false;
  }
  return (
    satisfiesSuiteConstraint(
      ownProperty<unknown>(constraint, 'alg'),
      ownProperty<string>(vc, 'alg'),
      budget,
    ) &&
    satisfiesSuiteConstraint(
      ownProperty<unknown>(constraint, 'proof_type'),
      ownProperty<string>(vc, 'proofType'),
      budget,
    ) &&
    satisfiesSuiteConstraint(
      ownProperty<unknown>(constraint, 'cryptosuite'),
      ownProperty<string>(vc, 'cryptosuite'),
      budget,
    ) &&
    satisfiesSuiteConstraint(
      ownProperty<unknown>(constraint, '-zkp_suite'),
      ownProperty<string>(vc, 'zkpSuite'),
      budget,
    )
  );
}
