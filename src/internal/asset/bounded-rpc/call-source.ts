/**
 * 本文サイズ・時間に上限のある既定 `EvmCallSource`。
 *
 * 以前の既定実装は ethers の `JsonRpcProvider` をそのまま使っていたため、RPC 応答に本文上限が無く
 * （25 MB の `eth_call` 応答で RSS 約 1.2 GB）、タイムアウトも ethers 既定の 300 秒だった。同じ SDK の
 * did:ethr（`identity/ethr/registry.ts`）・AA Bundler・SIWE ERC-1271 は `http/json-rpc.ts` の
 * `requestJsonRpc`（10 秒・1 MiB・redirect 非追従）へ統一済みなので、asset の RPC もこの 1 か所に揃える。
 * ここでは送信するメソッドと params、および応答値の検証方法を定義する。
 *
 * 結果の形状は外部由来なので、型（hex 文字列 / 256 ビット以下の quantity / 32 バイトハッシュ）を検査して
 * から返す。形状違反は `CHAIN_SUBMIT_FAILED`（1021）で、RPC URL・アドレス・金額・署名済み Tx などは
 * 例外に含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { requestJsonRpc } from '../../http/json-rpc.js';
import { keccak256 } from '../../keymanager/address.js';
import { bytesToHex, decodeHexDigits } from '../hex-codec.js';
import type {
  EvmCallRequest,
  EvmCallSource,
  EvmSendRequest,
  EvmTxEstimate,
  EvmTxParams,
} from '../rpc.js';

/** チェーン ID → RPC URL のマップ。 */
export type RpcUrls = Readonly<Record<number, string>>;

/** `0x` + 偶数桁 hex（`eth_call` の戻り値・生 Tx）。 */
const HEX_DATA = /^0x(?:[0-9a-fA-F]{2})*$/;
/** `0x` + 1〜64 桁 hex（256 ビット以下の quantity）。 */
const QUANTITY = /^0x[0-9a-fA-F]{1,64}$/;
/** `0x` + 64 桁 hex（トランザクションハッシュ）。 */
const HASH32 = /^0x[0-9a-fA-F]{64}$/;

function malformed(): VericertsError {
  return new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
}

function toQuantity(result: unknown): bigint {
  if (typeof result !== 'string' || !QUANTITY.test(result)) throw malformed();
  return BigInt(result);
}

/**
 * `requestJsonRpc` ベースの `EvmCallSource` を生成する。応答本文は 1 MiB、往復は 10 秒で打ち切る。
 *
 * @param rpcUrls チェーン ID → RPC URL マップ。未設定チェーンは `CHAIN_NOT_CONFIGURED`（4071）。
 * @param fetchImpl RPC 往復に使う fetch 実装（省略時はグローバル `fetch`。テスト注入用）。
 * @returns 本文・時間に上限のある `EvmCallSource`。
 */
export function createBoundedRpcCallSource(rpcUrls: RpcUrls, fetchImpl?: FetchLike): EvmCallSource {
  let nextId = 1;
  const rpc = (chainId: number, method: string, params: readonly unknown[]): Promise<unknown> => {
    const url = Object.hasOwn(rpcUrls, chainId) ? rpcUrls[chainId] : undefined;
    if (url === undefined) {
      // 未設定チェーンは解決不能（RPC マップ内容は伝播しない）。
      return Promise.reject(new VericertsError(ErrorCodes.CHAIN_NOT_CONFIGURED));
    }
    return requestJsonRpc(url, fetchImpl, nextId++, method, params, ErrorCodes.CHAIN_SUBMIT_FAILED);
  };

  return {
    async call(request: EvmCallRequest): Promise<string> {
      const result = await rpc(request.chainId, 'eth_call', [
        { to: request.to, data: request.data },
        'latest',
      ]);
      if (typeof result !== 'string' || !HEX_DATA.test(result)) throw malformed();
      return result;
    },
    async nativeBalance(chainId: number, address: string): Promise<bigint> {
      return toQuantity(await rpc(chainId, 'eth_getBalance', [address, 'latest']));
    },
    async fetchTxParams(chainId: number, from: string, tx: EvmTxEstimate): Promise<EvmTxParams> {
      const [nonce, gasLimit, gasPrice] = await Promise.all([
        rpc(chainId, 'eth_getTransactionCount', [from, 'pending']),
        rpc(chainId, 'eth_estimateGas', [
          { from, to: tx.to, data: tx.data, value: `0x${tx.value.toString(16)}` },
        ]),
        // legacy gasPrice を採用する（type 0 Tx）。取得できない場合は送信不能として扱う。
        rpc(chainId, 'eth_gasPrice', []),
      ]);
      const nonceValue = toQuantity(nonce);
      if (nonceValue > BigInt(Number.MAX_SAFE_INTEGER)) throw malformed();
      return {
        nonce: Number(nonceValue),
        gasLimit: toQuantity(gasLimit),
        gasPrice: toQuantity(gasPrice),
      };
    },
    async send(request: EvmSendRequest): Promise<string> {
      if (!HEX_DATA.test(request.rawTransaction)) throw malformed();
      const localHash = bytesToHex(keccak256(decodeHexDigits(request.rawTransaction.slice(2))));
      const returned = await rpc(request.chainId, 'eth_sendRawTransaction', [
        request.rawTransaction,
      ]);
      // 返却ハッシュは送った Tx のものと一致しなければならない（別 Tx を受理したと偽る応答を弾く）。
      if (typeof returned !== 'string' || !HASH32.test(returned)) throw malformed();
      if (returned.toLowerCase() !== localHash) throw malformed();
      return localHash;
    },
  };
}
