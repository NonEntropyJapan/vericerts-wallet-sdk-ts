/**
 * 緊急失効後のオンチェーン状態の確認。
 *
 * Bundler は利用者設定の第三者サービスで、`userOpHash`（SDK が署名した UserOperation から誰でも計算できる値）と
 * `success: true` を返すだけなら UserOperation を実行しなくても偽のレシートを作れる。レシートだけを根拠に
 * 「失効成功」を返すと、盗難端末の Validator が生き残ったまま呼び出し側が WUA 再発行へ進んでしまうため、
 * レシート確認後に**同じ `callSource` で `getValidators()` を読み直し**、失効対象が 1 件も残らず署名
 * Validator が残っていることを確認する。`callSource` と `bundlerRpc` は別エンドポイントで構成すること
 * （同一の侵害エンドポイントではこの確認も無力）。
 *
 * セキュリティ上の注意: アドレス・calldata・署名を例外に含めない。
 */

import { assertArrayResponseWithin } from '../asset/array-response.js';
import type { EvmCallSource } from '../asset/rpc.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { Hex } from './types.js';
import { createModularAccountAbiCodec } from './validator-abi.js';

/** ModularAccount が同時に install できる Validator の上限（`ERC4337Account._MAX_SIGNERS`）。 */
export const MAX_INSTALLED_VALIDATORS = 16;

/** 失効後の Validator 一覧の読み直し回数（`eth_call` 側ノードの 1 ブロック遅延を吸収する）。 */
const POST_STATE_READ_ATTEMPTS = 3;

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * ModularAccount の `getValidators()` を読む。install 済み Validator は ModularAccount 側で
 * {@link MAX_INSTALLED_VALIDATORS} 件までなので、それを超える応答（侵害 RPC が返す巨大 `address[]`）は
 * ABI デコード・再エンコードの前に `1021`（`phase: 'array_response_too_large'`）で拒否する。
 * 緊急失効と失効後の確認（本ファイル）が同じ読み取りを共有するため、検査も 1 か所に置く。
 */
export async function readInstalledValidators(
  callSource: EvmCallSource,
  chainId: number,
  accountAddress: Hex,
): Promise<Hex[]> {
  const codec = createModularAccountAbiCodec();
  const data = await callSource.call({
    chainId,
    to: accountAddress,
    data: codec.encode('getValidators', []),
  });
  assertArrayResponseWithin(data, MAX_INSTALLED_VALIDATORS);
  const [validators] = codec.decode('getValidators', data) as [readonly string[]];
  return validators.map((v) => v as Hex);
}

/** 緊急失効の期待状態（失効対象が全て消え、署名 Validator は残る）か。 */
function isExpectedPostState(
  installed: readonly Hex[],
  signingValidator: Hex,
  revoked: readonly Hex[],
): boolean {
  const present = new Set(installed.map((v) => v.toLowerCase()));
  return (
    present.has(signingValidator.toLowerCase()) &&
    revoked.every((v) => !present.has(v.toLowerCase()))
  );
}

/**
 * レシート `success` の後に Validator 状態を読み直し、実際に失効したことを確認する。
 *
 * 期待状態にならなければ（読み直しが `POST_STATE_READ_ATTEMPTS` 回とも不一致 / 読み取り失敗）、成功を返さず
 * `1021`（`phase: 'post_state_mismatch'` / `'post_state_unreadable'`）で拒否する。`userOpHash` / `txHash` は
 * 公開情報のため context に載せてよい。
 */
export async function confirmValidatorsRevoked(args: {
  readonly callSource: EvmCallSource;
  readonly chainId: number;
  readonly accountAddress: Hex;
  readonly signingValidatorAddress: Hex;
  readonly revokedValidators: readonly Hex[];
  readonly userOpHash: Hex;
  readonly txHash: Hex;
  readonly pollIntervalMs: number;
}): Promise<void> {
  const context = { userOpHash: args.userOpHash, txHash: args.txHash };
  let readFailed = false;
  for (let attempt = 0; attempt < POST_STATE_READ_ATTEMPTS; attempt++) {
    if (attempt > 0) {
      await sleep(args.pollIntervalMs);
    }
    try {
      const installed = await readInstalledValidators(
        args.callSource,
        args.chainId,
        args.accountAddress,
      );
      readFailed = false;
      if (isExpectedPostState(installed, args.signingValidatorAddress, args.revokedValidators)) {
        return;
      }
    } catch {
      readFailed = true;
    }
  }
  throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
    context: { phase: readFailed ? 'post_state_unreadable' : 'post_state_mismatch', ...context },
  });
}
