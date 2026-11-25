/**
 * `buildTrustChain` 1 回あたりの Statement 本文量の予算。
 *
 * Trust Chain は最大 `MAX_TRUST_CHAIN_LENGTH` 段で、Entity Configuration と Subordinate Statement を
 * 合わせて最大 9 通を取得する。各 Statement は `MAX_DOCUMENT_BYTES`（1 MiB）まで受け入れられるため、
 * 1 通ごとの上限だけでは、署名検証より前に攻撃者が選んだ本文 9 MiB 分の base64url デコード・JSON パースを
 * 強いられる（約 980 KB の `pad` を載せた 9 通で `buildTrustChain` が Node で約 3.4 秒停止した）。
 * 実在の Statement は数 KB なので、デコード・パースへ進む JWT の総文字数を連鎖全体で数えて縛る。
 *
 * 文字数予算は「Statement の比較・走査回数」を律しないので、`constraints`（§6.2）の強制が行う要素の
 * 走査・照合の総数（`allowed_entity_types` の件数・下位の `metadata` の Entity Type 数・名前制約の
 * 照合数）も別の予算 `remainingConstraintSteps` で連鎖全体について数える（予算内の 1.9 MB で
 * `allowed_entity_types` × `metadata` キーの総当たりが 9〜14 秒停止した）。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MAX_DOCUMENT_BYTES } from '../../../http/body-limit.js';

/** 1 回の Trust Chain 構築でデコード・パースへ進める JWT の総文字数（compact JWS は ASCII なのでバイト数と等しい）。 */
export const MAX_CHAIN_STATEMENT_CHARS = 2 * MAX_DOCUMENT_BYTES;

/**
 * 1 回の Trust Chain 構築で `constraints` の強制に費やせる走査・照合の総数。実在の連鎖は
 * Entity Type が数個・名前制約が数件なので桁違いに余裕があり、JWT 本文予算（2 MiB）内で作れる
 * 数十万要素の配列を使った増幅だけが超過する。
 */
export const MAX_CHAIN_CONSTRAINT_STEPS = 65_536;

/** Trust Chain 構築 1 回の Statement 本文量の残り（`buildTrustChain` が作り、各 Statement の検証が消費する）。 */
export interface StatementBudget {
  remainingChars: number;
  /** `constraints` の強制（`constraints/enforce.ts`）が使える走査・照合の残り。 */
  remainingConstraintSteps: number;
}

/** 新しい Statement 本文量・`constraints` 強制の予算を作る。 */
export function createStatementBudget(): StatementBudget {
  return {
    remainingChars: MAX_CHAIN_STATEMENT_CHARS,
    remainingConstraintSteps: MAX_CHAIN_CONSTRAINT_STEPS,
  };
}

/**
 * `jwt` をデコード・パースする前に、その長さを予算から差し引く。予算が無い呼び出し（`budget` 省略）は
 * 単独検証なので計上しない。尽きていたらデコードせず `TRUST_CHAIN_INVALID` で拒否する。
 *
 * @throws 残りが `jwt` の長さに足りない場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function consumeStatementBudget(budget: StatementBudget | undefined, jwt: string): void {
  if (budget === undefined) {
    return;
  }
  if (jwt.length > budget.remainingChars) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID, {
      context: { reason: 'statement_budget_exceeded' },
    });
  }
  budget.remainingChars -= jwt.length;
}

/**
 * `constraints` の強制が行う走査・照合 `steps` 回ぶんを、実行する前に予算から差し引く。
 * 予算が無い呼び出し（`budget` 省略）は単独検証なので計上しない。
 *
 * @throws 残りが `steps` に足りない場合（VericertsError、TRUST_CHAIN_INVALID）。
 */
export function consumeConstraintBudget(budget: StatementBudget | undefined, steps: number): void {
  if (budget === undefined) {
    return;
  }
  if (steps > budget.remainingConstraintSteps) {
    throw new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID, {
      context: { reason: 'constraint_budget_exceeded' },
    });
  }
  budget.remainingConstraintSteps -= steps;
}
