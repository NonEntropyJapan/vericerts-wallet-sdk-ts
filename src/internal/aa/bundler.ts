/**
 * ERC-4337 Bundler との JSON-RPC 通信。
 *
 * `BundlerRpc` seam を介してのみネットワークに触れる（asset の EvmCallSource と同方針）。既定実装は
 * fetch-adapter.ts の `createFetchBundlerRpc` が fetch で提供し、テストは fake な `BundlerRpc` を注入して
 * 実 RPC 非依存で検証できる。UserOperation の hex シリアライズ（bigint → hex / factory・paymaster の
 * unpacked 送信）と結果の正規化を本モジュールが担う。
 *
 * セキュリティ上の注意:
 * - Bundler URL・UserOp フィールド・エラー本文を例外 message / context / cause に伝播させない。
 *   トランスポート / レスポンス形状失敗は VericertsError（code `1021`、retriable）、
 *   Bundler が返す JSON-RPC error（UserOp 拒否）は code `7002` BUNDLER_REJECTED に正規化する（fetch-adapter.ts）。
 */

import { deepHexlify } from 'permissionless/utils';
import { ErrorCodes, VericertsError } from '../errors.js';
import { MetricNames, type Metrics } from '../observability/metrics.js';
import { safeEmit } from '../observability/safe-emit.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { assertGasWithinLimits } from './gas-limits.js';
import { fromHex } from './hex.js';
import {
  ENTRY_POINT_V07_ADDRESS,
  type Hex,
  type UserOperationGasEstimate,
  type UserOperationReceipt,
  type UserOperationV07,
} from './types.js';

/** Bundler の標準メソッド名（ERC-4337）。 */
const METHOD_SEND = 'eth_sendUserOperation';
const METHOD_ESTIMATE = 'eth_estimateUserOperationGas';
const METHOD_RECEIPT = 'eth_getUserOperationReceipt';
const METHOD_SUPPORTED = 'eth_supportedEntryPoints';

/**
 * Bundler JSON-RPC アクセスの seam。bundler.ts はこのインターフェース経由でのみネットワークに触れる。
 * 既定実装は fetch-adapter.ts の `createFetchBundlerRpc`。
 */
export interface BundlerRpc {
  /**
   * JSON-RPC メソッドを呼び、`result` を返す。Bundler が JSON-RPC error を返した場合（UserOp 拒否）は
   * VericertsError（code `7002` BUNDLER_REJECTED）、トランスポート / レスポンス形状失敗は code `1021` に
   * 正規化して throw する。
   *
   * @param method メソッド名。
   * @param params 位置パラメータ配列。
   * @returns `result`（呼び出し側が型を解釈する）。
   */
  request(method: string, params: readonly unknown[]): Promise<unknown>;
}

/**
 * UserOperationV07 を Bundler JSON-RPC の unpacked v0.7 表現へ変換する。
 *
 * permissionless.js（v0.2.x）の `deepHexlify` で全 bigint フィールドを hex 化し、`undefined` の
 * factory / paymaster フィールドは自動的に省略される（permissionless.js が Bundler 送信で用いるのと
 * 同一の正規化。主要 Bundler の unpacked v0.7 スキーマに準拠）。paymaster を使う場合は付随 gas を
 * 0n 既定で補完してから hexlify する。
 */
export function toRpcUserOperation(userOp: UserOperationV07): Record<string, string> {
  // 任意フィールドは own 限定で読む（`Object.prototype` 汚染値を送信表現へ載せない）。
  const normalized =
    ownProperty<Hex>(userOp, 'paymaster') !== undefined
      ? {
          ...userOp,
          paymasterVerificationGasLimit:
            ownProperty<bigint>(userOp, 'paymasterVerificationGasLimit') ?? 0n,
          paymasterPostOpGasLimit: ownProperty<bigint>(userOp, 'paymasterPostOpGasLimit') ?? 0n,
          paymasterData: ownProperty<Hex>(userOp, 'paymasterData') ?? '0x',
        }
      : userOp;
  return deepHexlify(normalized) as Record<string, string>;
}

/**
 * UserOperation を Bundler に送信し、UserOpHash を返す（eth_sendUserOperation）。
 *
 * `metrics` は任意（`vericerts_bundler_userop_total`、labels: `result`）。
 * 本モジュールは Wallet ファサードへ配線されていない独立した seam のため、注入元を強制せず
 * 未指定時は記録しない（`did.resolve` 等の必須注入とは異なり、呼び出し側は本 SDK 外の可能性がある）。
 *
 * @param rpc Bundler RPC seam。
 * @param userOp 署名済み UserOperation。
 * @param metrics 注入する場合のメトリクス出力先（省略可）。
 * @returns UserOpHash（`0x` プレフィックス付き hex）。
 * @throws RPC / トランスポート失敗・戻り値不正の場合（VericertsError、code `1021`）。
 */
export async function sendUserOperation(
  rpc: BundlerRpc,
  userOp: UserOperationV07,
  metrics?: Metrics,
): Promise<Hex> {
  const countResult = (result: 'success' | 'failure'): void =>
    // 送信結果を優先する。メトリクス sink の失敗で成功を reject に変えず、失敗カウンタの二重計上もしない。
    safeEmit(() => metrics?.counter(MetricNames.BUNDLER_USEROP_TOTAL, { result }).inc());
  let result: unknown;
  try {
    result = await rpc.request(METHOD_SEND, [toRpcUserOperation(userOp), ENTRY_POINT_V07_ADDRESS]);
    if (typeof result !== 'string' || !result.startsWith('0x')) {
      throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
    }
  } catch (error) {
    countResult('failure');
    throw error;
  }
  countResult('success');
  return result as Hex;
}

/**
 * UserOperation のガスを見積もる（eth_estimateUserOperationGas）。
 *
 * @param rpc Bundler RPC seam。
 * @param userOp 見積もり対象（署名は EMPTY_SIGNATURE でよい）。
 * @returns preVerificationGas / verificationGasLimit / callGasLimit（Paymaster 分は任意）。
 * @throws RPC / トランスポート失敗・戻り値不正の場合（VericertsError、code `1021`）。
 */
export async function estimateUserOperationGas(
  rpc: BundlerRpc,
  userOp: UserOperationV07,
): Promise<UserOperationGasEstimate> {
  const result = await rpc.request(METHOD_ESTIMATE, [
    toRpcUserOperation(userOp),
    ENTRY_POINT_V07_ADDRESS,
  ]);
  if (result === null || typeof result !== 'object') {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  const r = result as Record<string, unknown>;
  const estimate: UserOperationGasEstimate = {
    preVerificationGas: fromHex(r.preVerificationGas),
    verificationGasLimit: fromHex(r.verificationGasLimit),
    callGasLimit: fromHex(r.callGasLimit),
    ...(r.paymasterVerificationGasLimit !== undefined
      ? { paymasterVerificationGasLimit: fromHex(r.paymasterVerificationGasLimit) }
      : {}),
    ...(r.paymasterPostOpGasLimit !== undefined
      ? { paymasterPostOpGasLimit: fromHex(r.paymasterPostOpGasLimit) }
      : {}),
  };
  // Bundler 応答は信頼できない外部入力。巨大なガス値に署名するとアカウント資金をガス代名目で
  // 抜かれるため、呼び出し側へ返す前に絶対上限で弾く。
  assertGasWithinLimits(estimate);
  return estimate;
}

/**
 * UserOperation のレシートを取得する（eth_getUserOperationReceipt）。
 *
 * @param rpc Bundler RPC seam。
 * @param userOpHash 対象 UserOpHash。
 * @returns レシート。まだマイニングされていない場合は `null`。
 * @throws RPC / トランスポート失敗・戻り値不正・レシートの `userOpHash` が要求と不一致の場合
 *         （VericertsError、code `1021`。不一致は context `phase: 'receipt_userop_hash_mismatch'`）。
 */
export async function getUserOperationReceipt(
  rpc: BundlerRpc,
  userOpHash: Hex,
): Promise<UserOperationReceipt | null> {
  const result = await rpc.request(METHOD_RECEIPT, [userOpHash]);
  if (result === null) {
    return null;
  }
  if (typeof result !== 'object') {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  const r = result as Record<string, unknown>;
  const receipt = r.receipt as Record<string, unknown> | undefined;
  const txHash = receipt?.transactionHash ?? r.transactionHash;
  if (typeof r.userOpHash !== 'string' || typeof txHash !== 'string') {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  // 別の UserOperation のレシートを要求 hash のものとして受け入れない。Bundler（または中間者）が
  // 他 UserOp の成功レシートを返すだけで、緊急失効などが成立していないのに成功と誤認される。
  // hex の大文字小文字は同一値として扱う。context は公開情報（両 hash）のみ。
  if (r.userOpHash.toLowerCase() !== userOpHash.toLowerCase()) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED, {
      context: {
        phase: 'receipt_userop_hash_mismatch',
        userOpHash,
        returnedUserOpHash: r.userOpHash,
      },
    });
  }
  return {
    userOpHash: r.userOpHash as Hex,
    success: r.success === true,
    actualGasUsed: fromHex(r.actualGasUsed),
    actualGasCost: fromHex(r.actualGasCost),
    transactionHash: txHash as Hex,
  };
}

/**
 * Bundler が対応する EntryPoint アドレス一覧を取得する（eth_supportedEntryPoints）。
 *
 * @param rpc Bundler RPC seam。
 * @returns EntryPoint アドレスの配列。
 * @throws RPC / トランスポート失敗・戻り値不正の場合（VericertsError、code `1021`）。
 */
export async function getSupportedEntryPoints(rpc: BundlerRpc): Promise<Hex[]> {
  const result = await rpc.request(METHOD_SUPPORTED, []);
  if (!Array.isArray(result) || !result.every((v) => typeof v === 'string')) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  return result as Hex[];
}
