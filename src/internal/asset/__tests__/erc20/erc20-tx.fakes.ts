/** `erc20-tx` 系テストが共有する fake（codec / EvmCallSource）。 */

import type { AbiCodec } from '../../codec.js';
import type { EvmCallSource, EvmSendRequest, EvmTxEstimate, EvmTxParams } from '../../rpc.js';

/** 固定の calldata を返す fake codec（記録機能付き）。 */
export function fakeCodec(calldata = '0xa9059cbb'): {
  codec: AbiCodec;
  calls: { fn: string; args: readonly unknown[] }[];
} {
  const calls: { fn: string; args: readonly unknown[] }[] = [];
  return {
    codec: {
      encode(fn, args) {
        calls.push({ fn, args });
        return calldata;
      },
      // 送金経路では decode を使わない（read 用の seam メソッド）。
      decode() {
        throw new Error('not used');
      },
    },
    calls,
  };
}

/** 固定 params を返す fake EvmCallSource（fetchTxParams / send の記録付き）。 */
export function fakeCallSource(
  params: EvmTxParams = { nonce: 7, gasLimit: 65000n, gasPrice: 1_000_000_000n },
  txHash = '0xhash',
): {
  callSource: EvmCallSource;
  fetched: { chainId: number; from: string; tx: EvmTxEstimate }[];
  sent: EvmSendRequest[];
} {
  const fetched: { chainId: number; from: string; tx: EvmTxEstimate }[] = [];
  const sent: EvmSendRequest[] = [];
  return {
    callSource: {
      // 送金経路では read 用の call / nativeBalance は使わない。
      async call() {
        throw new Error('not used');
      },
      async nativeBalance() {
        throw new Error('not used');
      },
      async fetchTxParams(chainId, from, tx) {
        fetched.push({ chainId, from, tx });
        return params;
      },
      async send(request) {
        sent.push(request);
        return txHash;
      },
    },
    fetched,
    sent,
  };
}
