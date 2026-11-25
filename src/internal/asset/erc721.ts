/**
 * ERC-721 残高・所有判定・メタデータ取得。
 *
 * `balanceOf(owner)` / `ownerOf(tokenId)` / `tokenURI(tokenId)` を view 呼び出しで取得する。
 * 本モジュールは ethers に直接依存しない。ABI エンコード/デコードは `AbiCodec` seam、
 * RPC は `EvmCallSource` seam を介して行い、いずれも DI で注入される。ERC-721 用の既定
 * codec は ethers-adapter.ts の `createErc721AbiCodec` が提供する。これによりテストは
 * fake seam で完結し、ネットワーク・ethers 実体に依存しない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` にアドレス・残高・tokenId・tokenURI を含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import type { AbiCodec } from './codec.js';
import { assertAddress, decodeFirst, decodeUint256 } from './read-utils.js';
import type { EvmCallSource } from './rpc.js';

/** ERC-721 read 系関数の ABI シグネチャ（`AbiCodec` に渡す）。 */
const BALANCE_OF = 'balanceOf' as const;
const OWNER_OF = 'ownerOf' as const;
const TOKEN_URI = 'tokenURI' as const;

/**
 * ERC-721 read の依存（DI seam）。
 */
export interface Erc721ReadDeps {
  /** RPC view 呼び出しシーム（既定は ethers-adapter の `createEthersCallSource`）。 */
  readonly callSource: EvmCallSource;
  /** ERC-721 ABI エンコード/デコードシーム（既定は ethers-adapter の `createErc721AbiCodec`）。 */
  readonly codec: AbiCodec;
}

/**
 * ERC-721 トークンの保有数を取得する（`balanceOf(owner)`）。
 *
 * @param chainId 対象チェーン ID。
 * @param contractAddress NFT コントラクトアドレス（`0x` + 40 hex）。
 * @param ownerAddress 保有者アドレス（`0x` + 40 hex）。
 * @param deps RPC / ABI codec の DI。
 * @returns 保有トークン数（`bigint`）。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getErc721Balance(
  chainId: number,
  contractAddress: string,
  ownerAddress: string,
  deps: Erc721ReadDeps,
): Promise<bigint> {
  assertAddress(contractAddress);
  assertAddress(ownerAddress);
  const data = deps.codec.encode(BALANCE_OF, [ownerAddress]);
  const raw = await deps.callSource.call({ chainId, to: contractAddress, data });
  return decodeUint256(deps.codec, BALANCE_OF, raw);
}

/**
 * ERC-721 トークンの所有者アドレスを取得する（`ownerOf(tokenId)`）。
 *
 * @param chainId 対象チェーン ID。
 * @param contractAddress NFT コントラクトアドレス（`0x` + 40 hex）。
 * @param tokenId 対象トークン ID。
 * @param deps RPC / ABI codec の DI。
 * @returns 所有者アドレス（`0x` + 40 hex）。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getErc721Owner(
  chainId: number,
  contractAddress: string,
  tokenId: bigint,
  deps: Erc721ReadDeps,
): Promise<string> {
  assertAddress(contractAddress);
  const data = deps.codec.encode(OWNER_OF, [tokenId]);
  const raw = await deps.callSource.call({ chainId, to: contractAddress, data });
  return String(decodeFirst(deps.codec, OWNER_OF, raw));
}

/**
 * ERC-721 トークンの `tokenURI(tokenId)` を取得する（メタデータ URI）。
 *
 * @param chainId 対象チェーン ID。
 * @param contractAddress NFT コントラクトアドレス（`0x` + 40 hex）。
 * @param tokenId 対象トークン ID。
 * @param deps RPC / ABI codec の DI。
 * @returns メタデータ URI 文字列。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）・
 *         RPC 失敗（code `1021`）の場合（VericertsError）。
 */
export async function getErc721TokenUri(
  chainId: number,
  contractAddress: string,
  tokenId: bigint,
  deps: Erc721ReadDeps,
): Promise<string> {
  assertAddress(contractAddress);
  const data = deps.codec.encode(TOKEN_URI, [tokenId]);
  const raw = await deps.callSource.call({ chainId, to: contractAddress, data });
  return String(decodeFirst(deps.codec, TOKEN_URI, raw));
}

/**
 * 指定 owner が指定 tokenId を所有しているか判定する（`ownerOf` の大文字小文字非依存比較）。
 *
 * 列挙インデクサに依存せず、候補 tokenId 群について所有判定するための補助。所有していない
 * トークンに対する `ownerOf` は revert し得るため、その場合は所有なし（false）として扱う。
 *
 * @param chainId 対象チェーン ID。
 * @param contractAddress NFT コントラクトアドレス（`0x` + 40 hex）。
 * @param tokenId 対象トークン ID。
 * @param ownerAddress 判定対象の保有者アドレス（`0x` + 40 hex）。
 * @param deps RPC / ABI codec の DI。
 * @returns 所有していれば true。
 * @throws アドレス形式不正（code `4070`）・未設定チェーン（code `4071`）の場合（VericertsError）。
 */
export async function ownsErc721Token(
  chainId: number,
  contractAddress: string,
  tokenId: bigint,
  ownerAddress: string,
  deps: Erc721ReadDeps,
): Promise<boolean> {
  assertAddress(ownerAddress);
  try {
    const owner = await getErc721Owner(chainId, contractAddress, tokenId, deps);
    return owner.toLowerCase() === ownerAddress.toLowerCase();
  } catch (error) {
    // 未設定チェーン / アドレス形式不正は呼び出し側の前提エラーとして再送する。
    // 未所有トークンの ownerOf revert（RPC 失敗 1021）は「所有なし」に正規化する。
    if (error instanceof VericertsError && error.code !== ErrorCodes.CHAIN_SUBMIT_FAILED) {
      throw error;
    }
    return false;
  }
}
