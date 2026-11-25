/**
 * delegation の ethers 依存を隔離する既定実装アダプタ（書き込み Tx 構築用）。
 *
 * `changeOwner` をエンコードする `AbiEncoder` の
 * 既定実装を提供する。本ファイル「のみ」が delegation 配下で ethers に依存し、コア（tx.ts）は
 * 本アダプタを介してのみ ethers に触れる（ethr/registry.ts と同様の ethers 隔離方針）。
 *
 * イベント取得（controller 検出）は read 専用であり、did:ethrの `Erc1056EventSource`
 * （ethr/registry.ts の `createEthersEventSource`）を再利用する。書き込み Tx 構築は ethr に
 * 存在しないため、本アダプタが delegation 固有の write エンコーダとして担う。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・アドレスを含めない。
 */

import { Interface } from 'ethers';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { AbiEncoder } from './tx.js';

/**
 * ERC-1056 の最小 ABI（controller 設定／削除に必要な書き込み関数のみ）。
 *
 * `changeOwner(identity, newOwner)` を含む。read 系（イベント・
 * identityOwner）は ethr/registry.ts が担うため本アダプタには含めない。
 */
const ERC1056_WRITE_ABI = ['function changeOwner(address identity, address newOwner)'] as const;

/**
 * ethers の `Interface` を用いた既定 `AbiEncoder` を生成する（tx.ts に注入）。
 *
 * @returns ERC-1056 書き込み ABI に基づく `AbiEncoder`。
 */
export function createErc1056AbiEncoder(): AbiEncoder {
  const iface = new Interface(ERC1056_WRITE_ABI);
  return {
    encodeFunctionData(functionName: string, args: readonly unknown[]): string {
      try {
        return iface.encodeFunctionData(functionName, args as unknown[]);
      } catch (cause) {
        // 引数（アドレス）が cause に含まれ得るため cause を渡さず正規化する。
        void cause;
        throw new VericertsError(ErrorCodes.INVALID_DID);
      }
    },
  };
}
