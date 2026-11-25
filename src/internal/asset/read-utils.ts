/**
 * asset read 系（ERC-20 残高取得 / ERC-721・ERC-1155 一覧取得）で共有する
 * アドレス検証・戻り値デコードの補助。
 *
 * eth_call の生戻り値を `AbiCodec` でデコードし、欠落時を VericertsError に正規化する。
 * これにより素の `TypeError` や `NaN` / 文字列 `'undefined'` のサイレント不正値を防ぐ。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` にアドレス・残高・引数値・tokenId・uri を含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { isValidEvmAddress } from '../evm-format.js';
import type { AbiCodec } from './codec.js';

/**
 * EVM アドレス形式を検証する。
 *
 * @param address 検証対象アドレス。
 * @throws 形式不正の場合（VericertsError、code `4070`。アドレス値は伝播しない）。
 */
export function assertAddress(address: string): void {
  if (!isValidEvmAddress(address)) {
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }
}

/**
 * 戻り値をデコードし、先頭要素を取り出す。
 *
 * `noUncheckedIndexedAccess` 下で `decoded[0]` は `unknown | undefined` であり、codec が
 * 空配列を返す（コントラクト不在・想定外戻り値で ethers が空配列を返す等）と `undefined`
 * になる。この値を `BigInt`/`Number`/`String` に直接渡すと素の `TypeError` や `NaN`・
 * 文字列 `'undefined'` といったサイレント不正値になるため、欠落時はここで VericertsError
 * （code `1021`、デコード失敗）に正規化する。アドレス・残高などの値は例外に含めない。
 *
 * @param codec ABI codec。
 * @param fn ABI 関数名（戻り値型の解決に用いる）。
 * @param raw eth_call の生戻り値（hex）。
 * @returns デコード結果の先頭要素（`undefined` ではないことが保証される）。
 * @throws デコード結果が空の場合（VericertsError、code `1021`）。
 */
export function decodeFirst(codec: AbiCodec, fn: string, raw: string): NonNullable<unknown> {
  const decoded = codec.decode(fn, raw);
  const value = decoded[0];
  if (value === undefined || value === null) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  return value;
}

/**
 * `uint256` 戻り値をデコードして `bigint` に正規化する。
 *
 * @param codec ABI codec。
 * @param fn ABI 関数名（戻り値型の解決に用いる）。
 * @param raw eth_call の生戻り値（hex）。
 * @returns デコードした `bigint`。
 * @throws デコード結果が空の場合（VericertsError、code `1021`）。
 */
export function decodeUint256(codec: AbiCodec, fn: string, raw: string): bigint {
  return BigInt(decodeFirst(codec, fn, raw) as bigint | number | string);
}
