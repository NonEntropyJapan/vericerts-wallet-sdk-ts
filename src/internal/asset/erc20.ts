/**
 * ERC-20 残高・メタデータ取得。
 *
 * `balanceOf(address)` / `decimals()` / `symbol()` を view 呼び出しで取得する。
 * 本モジュールは ethers に直接依存しない。ABI エンコード/デコードは `AbiCodec` seam、
 * RPC は `EvmCallSource` seam を介して行い、いずれも DI で注入される。既定実装は
 * ethers-adapter.ts が提供する。これによりテストは fake seam で完結し、ネットワーク・
 * ethers 実体に依存しない。
 *
 * 残高は `bigint`（最小単位、未整形）で正確に扱う。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` にアドレス・残高・RPC URL を含めない。
 */

import type { AbiCodec } from './codec.js';
import { assertAddress, decodeFirst, decodeUint256 } from './read-utils.js';
import type { EvmCallSource } from './rpc.js';

/** ETH（ネイティブ残高）を表す擬似トークンアドレス。 */
export const NATIVE_TOKEN_ADDRESS = '0x0';

/** ERC-20 read 系関数の ABI 関数名（`AbiCodec` に渡す）。 */
const BALANCE_OF = 'balanceOf' as const;
const DECIMALS = 'decimals' as const;
const SYMBOL = 'symbol' as const;

/**
 * ERC-20 read の依存（DI seam）。
 */
export interface Erc20ReadDeps {
  /** RPC view 呼び出しシーム（既定は ethers-adapter の `createEthersCallSource`）。 */
  readonly callSource: EvmCallSource;
  /** ABI エンコード/デコードシーム（既定は ethers-adapter の `createErc20AbiCodec`）。 */
  readonly codec: AbiCodec;
}

/**
 * ERC-20 トークン残高を取得する（最小単位の `bigint`）。
 *
 * `tokenAddress` が `"0x0"`（NATIVE_TOKEN_ADDRESS）の場合は ETH ネイティブ残高を取得する。
 * それ以外は `balanceOf(holder)` を eth_call で読み取り、戻り値を `uint256` としてデコードする。
 *
 * @param chainId 対象チェーン ID（Mainnet=1 / Arbitrum=42161 / Soneium=1868 / Filecoin=314）。
 * @param holderAddress 保有者アドレス（`0x` + 40 hex）。
 * @param tokenAddress トークンコントラクトアドレス、または `"0x0"`（ETH）。
 * @param deps RPC / ABI codec の DI。
 * @returns 残高（最小単位、未整形の `bigint`）。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getTokenBalance(
  chainId: number,
  holderAddress: string,
  tokenAddress: string,
  deps: Erc20ReadDeps,
): Promise<bigint> {
  assertAddress(holderAddress);
  if (tokenAddress === NATIVE_TOKEN_ADDRESS) {
    return deps.callSource.nativeBalance(chainId, holderAddress);
  }
  assertAddress(tokenAddress);
  const data = deps.codec.encode(BALANCE_OF, [holderAddress]);
  const raw = await deps.callSource.call({ chainId, to: tokenAddress, data });
  return decodeUint256(deps.codec, BALANCE_OF, raw);
}

/**
 * ERC-20 `decimals()` を取得する。
 *
 * @param chainId 対象チェーン ID。
 * @param tokenAddress トークンコントラクトアドレス（`0x` + 40 hex）。
 * @param deps RPC / ABI codec の DI。
 * @returns 小数桁数（0〜255）。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getTokenDecimals(
  chainId: number,
  tokenAddress: string,
  deps: Erc20ReadDeps,
): Promise<number> {
  assertAddress(tokenAddress);
  const data = deps.codec.encode(DECIMALS, []);
  const raw = await deps.callSource.call({ chainId, to: tokenAddress, data });
  const value = decodeFirst(deps.codec, DECIMALS, raw);
  return Number(value as bigint | number);
}

/**
 * ERC-20 `symbol()` を取得する。
 *
 * @param chainId 対象チェーン ID。
 * @param tokenAddress トークンコントラクトアドレス（`0x` + 40 hex）。
 * @param deps RPC / ABI codec の DI。
 * @returns トークンシンボル文字列。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getTokenSymbol(
  chainId: number,
  tokenAddress: string,
  deps: Erc20ReadDeps,
): Promise<string> {
  assertAddress(tokenAddress);
  const data = deps.codec.encode(SYMBOL, []);
  const raw = await deps.callSource.call({ chainId, to: tokenAddress, data });
  return String(decodeFirst(deps.codec, SYMBOL, raw));
}
