/**
 * `PaymasterClient` の既定実装（fetch ベースの ERC-7677 JSON-RPC トランスポート）。
 *
 * ネットワークに触れるのは共通の `http/json-rpc.ts` の {@link requestJsonRpc} だけで、本ファイルは ERC-7677 固有の params 組み立てと
 * 正規化先のエラーコードだけを持つ（タイムアウト・本文上限・seam 解決を 2 か所に書き写さない）。
 * paymaster.ts は `PaymasterClient` seam 経由でのみ通信し、テストは fake seam を注入して本アダプタに
 * 依存しない。
 *
 * UserOperation は Bundler と同じ unpacked v0.7 hex 表現（`toRpcUserOperation`）で送信し、
 * `pm_getPaymasterStubData` / `pm_getPaymasterData` の第 2・第 3 引数に EntryPoint アドレスと
 * chainId（hex）を渡す（ERC-7677）。
 *
 * セキュリティ上の注意:
 * - Paymaster URL・レスポンス本文・JSON-RPC error message を VericertsError の message / context /
 *   cause に伝播させない。トランスポート / レスポンス形状失敗は code `1021`
 *   （retriable）、Paymaster が返す JSON-RPC error（Sponsorship 拒否）は code `7003` PAYMASTER_REJECTED に正規化する。
 */

import { ErrorCodes } from '../errors.js';
import { requestJsonRpc } from '../http/json-rpc.js';
import { toRpcUserOperation } from './bundler.js';
import type { FetchLike } from './fetch-adapter.js';
import {
  normalizePaymasterFields,
  PAYMASTER_METHOD_DATA,
  PAYMASTER_METHOD_STUB,
  type PaymasterClient,
  type PaymasterFields,
} from './paymaster.js';
import { ENTRY_POINT_V07_ADDRESS, type UserOperationV07 } from './types.js';

/** JSON-RPC リクエスト ID の連番カウンタ用の初期値。 */
const INITIAL_ID = 1;

/**
 * fetch ベースの `PaymasterClient` を生成する（ERC-7677）。
 *
 * @param url Paymaster サービスの JSON-RPC エンドポイント URL。
 * @param fetchImpl fetch 実装（未指定はグローバル `fetch`。テストで注入可能）。
 * @returns `PaymasterClient` 実装。
 */
export function createFetchPaymasterClient(url: string, fetchImpl?: FetchLike): PaymasterClient {
  let nextId = INITIAL_ID;

  async function request(
    method: string,
    userOp: UserOperationV07,
    chainId: number,
  ): Promise<PaymasterFields> {
    const params = [
      toRpcUserOperation(userOp),
      ENTRY_POINT_V07_ADDRESS,
      `0x${chainId.toString(16)}`,
    ];
    const result = await requestJsonRpc(
      url,
      fetchImpl,
      nextId++,
      method,
      params,
      ErrorCodes.PAYMASTER_REJECTED,
    );
    return normalizePaymasterFields(result);
  }

  return {
    getPaymasterStubData(userOp, chainId) {
      return request(PAYMASTER_METHOD_STUB, userOp, chainId);
    },
    getPaymasterData(userOp, chainId) {
      return request(PAYMASTER_METHOD_DATA, userOp, chainId);
    },
  };
}
