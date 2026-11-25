/**
 * asset モジュールの対応チェーン定義とマルチチェーン解決。
 *
 * 対応するチェーン名は `"mainnet"` / `"arbitrum"` / `"soneium"` / `"filecoin"` で、
 * Chain ID はそれぞれ `1` / `42161` / `1868` / `314`。ERC-20 残高取得は EVM 互換ネットワークを対象とし、
 * 本ファイルがチェーン名 ⇄ chainId の解決を担う純粋ロジック（ネットワーク・ethers 非依存）を提供する。
 * Filecoin は f410 に対応する `0x`（EVM 互換）アドレスのみを扱い、`f1` / `f3` / `f410f…` 形式は扱わない。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` にアドレス・残高・RPC URL を含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

/**
 * asset 対応チェーンのデータ enum。
 */
export type AssetChain = 'mainnet' | 'arbitrum' | 'soneium' | 'filecoin';

/**
 * チェーン名から Chain ID を引くマップ。
 */
export const ASSET_CHAIN_IDS: Readonly<Record<AssetChain, number>> = {
  mainnet: 1,
  arbitrum: 42161,
  soneium: 1868,
  filecoin: 314,
} as const;

/** Chain ID → チェーン名の逆引きマップ（`resolveChainName` 用）。 */
const CHAIN_NAME_BY_ID: ReadonlyMap<number, AssetChain> = new Map(
  (Object.entries(ASSET_CHAIN_IDS) as [AssetChain, number][]).map(([name, id]) => [id, name]),
);

/**
 * 対応チェーン名から Chain ID を解決する。
 *
 * @param chain 対応チェーン名（`mainnet` / `arbitrum` / `soneium` / `filecoin`）。
 * @returns 対応する Chain ID。
 */
export function resolveChainId(chain: AssetChain): number {
  return ASSET_CHAIN_IDS[chain];
}

/**
 * Chain ID から対応チェーン名を解決する。
 *
 * @param chainId Chain ID。
 * @returns 対応するチェーン名。
 * @throws 未対応 Chain ID の場合（VericertsError、code `4071`）。
 */
export function resolveChainName(chainId: number): AssetChain {
  const name = CHAIN_NAME_BY_ID.get(chainId);
  if (name === undefined) {
    throw new VericertsError(ErrorCodes.CHAIN_NOT_CONFIGURED);
  }
  return name;
}

/**
 * Chain ID が asset 対応チェーンか判定する。
 *
 * @param chainId Chain ID。
 * @returns 対応チェーンなら `true`。
 */
export function isSupportedChainId(chainId: number): boolean {
  return CHAIN_NAME_BY_ID.has(chainId);
}
