/**
 * EOA（legacy Tx）送金の `gasLimit` / `gasPrice` の上限検査。
 *
 * `EvmCallSource.fetchTxParams` の戻り値は信頼境界外の RPC 由来で、そのまま署名すると侵害 RPC が
 * `eth_gasPrice` に極端に高い値（例: 50,000 gwei）を返すだけで、トークン 1 unit の送金に最大手数料 5 ETH の
 * 有効な署名済み Tx を作らせ、残高をガス代名目で抜き取れる。UserOperation 経路の
 * （`aa/gas-limits.ts`）と同じ方針で、署名前に絶対上限と総手数料上限で fail-closed に拒否する。
 *
 * - `gasLimit` は {@link MAX_TX_GAS_LIMIT}。UserOperation の `callGasLimit` 上限（`aa/gas-limits.ts` の
 *   `MAX_TX_GAS_LIMIT`）と同じ値を共有する（asset は Foundation のため、定義は asset 側に置き aa が参照する）。
 * - `gasPrice` は絶対上限 {@link MAX_GAS_PRICE_WEI}。
 * - `gasLimit × gasPrice` は {@link DEFAULT_MAX_TX_FEE_WEI}（呼び出し側の `maxTotalCostWei` で上書き）以内。
 *
 * 拒否は code `1021`（`CHAIN_SUBMIT_FAILED`）。値は例外に含めず、`context.phase` と対象フィールドのみ載せる。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

/** 1 Tx の `gasLimit` の絶対上限（gas）。Bundler 実装の既定 callGas 上限（10M）に揃える。 */
export const MAX_TX_GAS_LIMIT = 10_000_000n;

/** `gasPrice` の絶対上限（wei）= 2,000 gwei。過去の最大級の混雑時でも通常 Tx はこの内側に収まる。 */
export const MAX_GAS_PRICE_WEI = 2_000n * 1_000_000_000n;

/** 総手数料（`gasLimit × gasPrice`）の既定上限（wei）= 1 ネイティブトークン。 */
export const DEFAULT_MAX_TX_FEE_WEI = 1_000_000_000_000_000_000n;

function reject(phase: string, field?: string): VericertsError {
  return new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
    context: field === undefined ? { phase } : { phase, field },
  });
}

/**
 * 手数料予算（`maxTotalCostWei`）が「非負の bigint」であることを保証する。
 *
 * `NaN` / `Infinity` / 文字列 / オブジェクトは `gasLimit * gasPrice > maxTotalCostWei` を常に偽にして
 * 上限を黙って無効化する（`bigint` と非 `bigint` の比較は例外にならず偽になる）ため、型で拒否する。
 * 負値は全 Tx を拒否する設定として無意味（設定ミス）なので同様に拒否する。
 *
 * @throws bigint でない・負値の場合（VericertsError、code `1021`）。値は含めない。
 */
export function assertValidFeeBudget(maxTotalCostWei: unknown): asserts maxTotalCostWei is bigint {
  if (typeof maxTotalCostWei !== 'bigint' || maxTotalCostWei < 0n) {
    throw reject('gas_budget_invalid');
  }
}

/**
 * Tx の `gasLimit` / `gasPrice` と総手数料が上限以内であることを保証する。
 *
 * `tx` は RPC 由来（信頼境界外）なので `gasLimit` / `gasPrice` の型も検査する。`bigint` 以外
 * （`NaN` / 数値 / 文字列）は比較が常に偽になり絶対上限・総額上限をすり抜けるため拒否する。
 *
 * @param tx 検査対象（`gasLimit` / `gasPrice`）。
 * @param maxTotalCostWei 総手数料の上限（wei）。**`undefined`（省略）のときだけ**
 *        {@link DEFAULT_MAX_TX_FEE_WEI}。呼び出し側は `Object.prototype` を鎖読みせず own 限定で読むこと。
 * @throws 型不正・負値・絶対上限超過・総手数料超過の場合（VericertsError、code `1021`）。値は含めない。
 */
export function assertTxFeeWithinLimits(
  tx: { readonly gasLimit: bigint; readonly gasPrice: bigint },
  maxTotalCostWei: unknown = DEFAULT_MAX_TX_FEE_WEI,
): void {
  assertValidFeeBudget(maxTotalCostWei);
  if (typeof tx.gasLimit !== 'bigint' || tx.gasLimit < 0n || tx.gasLimit > MAX_TX_GAS_LIMIT) {
    throw reject('gas_limit_exceeded', 'gasLimit');
  }
  if (typeof tx.gasPrice !== 'bigint' || tx.gasPrice < 0n || tx.gasPrice > MAX_GAS_PRICE_WEI) {
    throw reject('gas_limit_exceeded', 'gasPrice');
  }
  if (tx.gasLimit * tx.gasPrice > maxTotalCostWei) {
    throw reject('gas_cost_exceeded');
  }
}
