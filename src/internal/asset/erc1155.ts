/**
 * ERC-1155 残高・メタデータ取得。
 *
 * `balanceOf(account, id)` / `balanceOfBatch(accounts, ids)` / `uri(id)` を view 呼び出しで
 * 取得する。本モジュールは ethers に直接依存しない。ABI エンコード/デコードは `AbiCodec`
 * seam、RPC は `EvmCallSource` seam を介して行い、いずれも DI で注入される。ERC-1155 用の
 * 既定 codec は ethers-adapter.ts の `createErc1155AbiCodec` が提供する。これによりテストは
 * fake seam で完結し、ネットワーク・ethers 実体に依存しない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` にアドレス・残高・id・uri を含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { assertArrayResponseWithin } from './array-response.js';
import type { AbiCodec } from './codec.js';
import { assertAddress, decodeFirst, decodeUint256 } from './read-utils.js';
import type { EvmCallSource } from './rpc.js';

/** ERC-1155 read 系関数の ABI シグネチャ（`AbiCodec` に渡す）。 */
const BALANCE_OF = 'balanceOf' as const;
const BALANCE_OF_BATCH = 'balanceOfBatch' as const;
const URI = 'uri' as const;

/** `balanceOfBatch` 1 回あたりの最大件数（応答のデコード量の上限）。 */
export const MAX_BALANCE_OF_BATCH = 1024;

/**
 * ERC-1155 read の依存（DI seam）。
 */
export interface Erc1155ReadDeps {
  /** RPC view 呼び出しシーム（既定は ethers-adapter の `createEthersCallSource`）。 */
  readonly callSource: EvmCallSource;
  /** ERC-1155 ABI エンコード/デコードシーム（既定は ethers-adapter の `createErc1155AbiCodec`）。 */
  readonly codec: AbiCodec;
}

/**
 * ERC-1155 トークンの残高を取得する（`balanceOf(account, id)`）。
 *
 * @param chainId 対象チェーン ID。
 * @param contractAddress NFT コントラクトアドレス（`0x` + 40 hex）。
 * @param accountAddress 保有者アドレス（`0x` + 40 hex）。
 * @param tokenId 対象トークン ID。
 * @param deps RPC / ABI codec の DI。
 * @returns 残高（`bigint`）。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getErc1155Balance(
  chainId: number,
  contractAddress: string,
  accountAddress: string,
  tokenId: bigint,
  deps: Erc1155ReadDeps,
): Promise<bigint> {
  assertAddress(contractAddress);
  assertAddress(accountAddress);
  const data = deps.codec.encode(BALANCE_OF, [accountAddress, tokenId]);
  const raw = await deps.callSource.call({ chainId, to: contractAddress, data });
  return decodeUint256(deps.codec, BALANCE_OF, raw);
}

/**
 * ERC-1155 トークンの残高を一括取得する（`balanceOfBatch(accounts, ids)`）。
 *
 * `accounts` と `ids` は同じ長さで対応付けられる（ERC-1155 仕様）。長さ不一致は入力誤りとして
 * `INVALID_EVM_ADDRESS`（4070）に正規化する（値は伝播しない）。
 *
 * @param chainId 対象チェーン ID。
 * @param contractAddress NFT コントラクトアドレス（`0x` + 40 hex）。
 * @param accountAddresses 保有者アドレスの配列（各 `0x` + 40 hex）。
 * @param tokenIds 対象トークン ID の配列（`accountAddresses` と同長）。
 * @param deps RPC / ABI codec の DI。
 * @returns 各 (account, id) に対応する残高の配列（`bigint[]`）。
 * @throws アドレス形式不正・長さ不一致（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getErc1155BalanceBatch(
  chainId: number,
  contractAddress: string,
  accountAddresses: readonly string[],
  tokenIds: readonly bigint[],
  deps: Erc1155ReadDeps,
): Promise<bigint[]> {
  assertAddress(contractAddress);
  if (accountAddresses.length !== tokenIds.length || tokenIds.length > MAX_BALANCE_OF_BATCH) {
    // accounts / ids の長さ不一致は ERC-1155 仕様違反、過大な件数は応答のデコード量を縛れない（入力誤り）。
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }
  for (const account of accountAddresses) {
    assertAddress(account);
  }
  const data = deps.codec.encode(BALANCE_OF_BATCH, [accountAddresses, tokenIds]);
  const raw = await deps.callSource.call({ chainId, to: contractAddress, data });
  // デコード前に「要求した件数」を上限として応答の形を検査する（ethers のデコードは件数に二次時間）。
  assertArrayResponseWithin(raw, tokenIds.length);
  const balances = decodeFirst(deps.codec, BALANCE_OF_BATCH, raw);
  if (!Array.isArray(balances) || balances.length !== tokenIds.length) {
    // balanceOfBatch は要求と同数の uint256[] を返す。配列でない・件数が合わない戻り値は想定外。
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  return balances.map((value) => BigInt(value as bigint | number | string));
}

/**
 * ERC-1155 トークンの `uri(id)` を取得する（メタデータ URI）。
 *
 * ERC-1155 の `uri` は `{id}` プレースホルダを含み得る（クライアント側で 64 桁 16 進・
 * 小文字ゼロ詰めの id に置換する仕様）。本関数はコントラクトの返す生の URI 文字列をそのまま
 * 返し、置換はより上位（facade）に委ねる。
 *
 * @param chainId 対象チェーン ID。
 * @param contractAddress NFT コントラクトアドレス（`0x` + 40 hex）。
 * @param tokenId 対象トークン ID。
 * @param deps RPC / ABI codec の DI。
 * @returns メタデータ URI 文字列（`{id}` プレースホルダ未置換）。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getErc1155Uri(
  chainId: number,
  contractAddress: string,
  tokenId: bigint,
  deps: Erc1155ReadDeps,
): Promise<string> {
  assertAddress(contractAddress);
  const data = deps.codec.encode(URI, [tokenId]);
  const raw = await deps.callSource.call({ chainId, to: contractAddress, data });
  return String(decodeFirst(deps.codec, URI, raw));
}
