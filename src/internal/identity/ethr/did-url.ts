/**
 * did:ethr の DID URL パース。
 *
 * did:ethr は ERC-1056 DID Registry に紐づく EVM アドレスベースの DID:
 *   `did:ethr:<address>`            # Mainnet（chainId = 1）
 *   `did:ethr:<chainId>:<address>`  # 他チェーン（chainId は 10 進数のみ）
 *
 * 本モジュールはネットワーク非依存の純粋なパースのみを担う。RPC 接続や
 * イベントスキャンは registry.ts / method-ethr.ts が担当する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・アドレスなどの入力データを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isValidCaip2ChainId, isValidEvmAddress } from '../../evm-format.js';

/** `did:ethr:` メソッドプレフィックス。 */
const DID_ETHR_PREFIX = 'did:ethr:';

/** 省略形（chainId 省略）の既定 chainId（Ethereum Mainnet）。 */
const DEFAULT_CHAIN_ID = 1;

/**
 * did:ethr のパース結果。
 */
export interface ParsedDidEthr {
  /** チェーン ID（10 進整数）。省略形では 1（Mainnet）。 */
  readonly chainId: number;
  /** EVM アドレス（`0x` + 40 hex、入力の大小文字を保持）。 */
  readonly address: string;
}

/**
 * did:ethr 文字列をパースする。
 *
 * 手順:
 * 1. `did:ethr:` プレフィックスを検証・除去。
 * 2. 残りを `:` で分割し、`<address>`（省略形）または `<chainId>:<address>` を期待。
 * 3. chainId は 10 進数の数字列のみ許容（`0x` hex chainId は不正として 2001）。
 *    address は `0x` + 40 hex（EIP-55 チェックサム / 素の小文字いずれも許容、保持）。
 *
 * @param did did:ethr 文字列。
 * @returns パース結果（chainId / address）。
 * @throws プレフィックス不正・セグメント過不足・chainId 非数字（0x hex 含む）・
 *         address 形式不正の場合（VericertsError、code `2001`）。入力は message に含めない。
 */
export function parseDidEthr(did: string): ParsedDidEthr {
  if (!did.startsWith(DID_ETHR_PREFIX)) {
    // 入力 DID はメッセージに含めない。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const methodSpecificId = did.slice(DID_ETHR_PREFIX.length);
  const segments = methodSpecificId.split(':');

  if (segments.length === 1) {
    const [address] = segments as [string];
    assertAddress(address);
    return { chainId: DEFAULT_CHAIN_ID, address };
  }

  if (segments.length === 2) {
    const [chainIdPart, address] = segments as [string, string];
    if (!isValidCaip2ChainId(chainIdPart)) {
      // 0x hex chainId や非数字は不正。
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    const chainId = Number(chainIdPart);
    if (!Number.isSafeInteger(chainId)) {
      // Number.MAX_SAFE_INTEGER 超は精度劣化するため不正扱い（入力は message に含めない）。
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    assertAddress(address);
    return { chainId, address };
  }

  // 余分なセグメントは不正。
  throw new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * EVM アドレス形式（`0x` + 40 hex）を検証する。
 *
 * @param address 検証対象アドレス。
 * @throws 形式不正の場合（VericertsError、code `2001`）。
 */
function assertAddress(address: string): void {
  if (!isValidEvmAddress(address)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}
