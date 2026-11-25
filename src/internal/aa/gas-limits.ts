/**
 * Bundler / Paymaster が返すガス値の上限検査。
 *
 * `eth_estimateUserOperationGas` / `pm_getPaymasterData` の応答は信頼できない外部入力だが、そのまま
 * UserOperation に取り込んで署名すると、悪意ある / 侵害された / MITM された Bundler が巨大なガス値で
 * アカウントの prefund（`(検証 + 実行 + preVerificationGas + paymaster 分) * maxFeePerGas`）を
 * 消費できる。特に `preVerificationGas` は全額が実使用ガスとして Bundler（beneficiary）へ支払われる。
 * 署名前に境界で現実的な絶対上限を超える値を拒否する（fail-closed）。
 *
 * 絶対上限は 1 UserOperation として現実的な桁（Bundler 実装の既定上限は概ね callGas 10M・
 * verificationGas 数百万・preVerificationGas 数十万）に十分な余裕を持たせた値。上限を超える見積りは
 * 正当でも拒否する（署名鍵が盗まれた直後に使う緊急経路では、不明な高額見積りに署名しないことを優先する）。
 *
 * セキュリティ上の注意: 拒否した値は例外に含めない。code `1021`
 * （`CHAIN_SUBMIT_FAILED`）に正規化し、`context.phase` と超過したフィールド名のみ載せる。
 */

import { assertValidFeeBudget, MAX_TX_GAS_LIMIT } from '../asset/tx-fee-limits.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import type { UserOperationV07 } from './types.js';

/** `preVerificationGas` の絶対上限（gas）。 */
export const MAX_PRE_VERIFICATION_GAS = 1_000_000n;
/** `verificationGasLimit` の絶対上限（gas）。 */
export const MAX_VERIFICATION_GAS_LIMIT = 5_000_000n;
/** `callGasLimit` の絶対上限（gas）。 */
export const MAX_CALL_GAS_LIMIT = MAX_TX_GAS_LIMIT;
/** `paymasterVerificationGasLimit` の絶対上限（gas）。 */
export const MAX_PAYMASTER_VERIFICATION_GAS_LIMIT = 5_000_000n;
/** `paymasterPostOpGasLimit` の絶対上限（gas）。 */
export const MAX_PAYMASTER_POST_OP_GAS_LIMIT = 5_000_000n;

/** 上限検査の対象フィールドと絶対上限。 */
const GAS_FIELD_LIMITS = {
  preVerificationGas: MAX_PRE_VERIFICATION_GAS,
  verificationGasLimit: MAX_VERIFICATION_GAS_LIMIT,
  callGasLimit: MAX_CALL_GAS_LIMIT,
  paymasterVerificationGasLimit: MAX_PAYMASTER_VERIFICATION_GAS_LIMIT,
  paymasterPostOpGasLimit: MAX_PAYMASTER_POST_OP_GAS_LIMIT,
} as const;

type GasField = keyof typeof GAS_FIELD_LIMITS;

/** 上限検査にかけるガスフィールド（未指定は検査対象外）。 */
export type GasFields = { readonly [K in GasField]?: bigint };

/**
 * ガスフィールドが絶対上限以内であることを保証する。
 *
 * @param fields 検査対象（未指定フィールドは無視する）。
 * @throws 負値または上限超過のフィールドがある場合（VericertsError、code `1021`）。値は含めない。
 */
export function assertGasWithinLimits(fields: GasFields): void {
  for (const field of Object.keys(GAS_FIELD_LIMITS) as GasField[]) {
    const value = fields[field];
    if (value === undefined) continue;
    if (value < 0n || value > GAS_FIELD_LIMITS[field]) {
      throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
        context: { phase: 'gas_limit_exceeded', field },
      });
    }
  }
}

/**
 * UserOperation の最悪ケース prefund（全ガス上限の合計 × `maxFeePerGas`）が `maxTotalCostWei` 以内
 * であることを保証する。呼び出し側が「このガス代までなら自動で払ってよい」と明示した予算の強制。
 *
 * @throws 予算超過の場合（VericertsError、code `1021`）。金額は含めない。
 */
export function assertTotalGasCostWithin(userOp: UserOperationV07, maxTotalCostWei: unknown): void {
  // bigint 以外（NaN / Infinity / 文字列）は比較が常に偽になり予算を黙って無効化するため拒否する。
  assertValidFeeBudget(maxTotalCostWei);
  const totalGas =
    userOp.preVerificationGas +
    userOp.verificationGasLimit +
    userOp.callGasLimit +
    (ownProperty<bigint>(userOp, 'paymasterVerificationGasLimit') ?? 0n) +
    (ownProperty<bigint>(userOp, 'paymasterPostOpGasLimit') ?? 0n);
  if (totalGas * userOp.maxFeePerGas > maxTotalCostWei) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
      context: { phase: 'gas_cost_exceeded' },
    });
  }
}
