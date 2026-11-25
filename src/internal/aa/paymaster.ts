/**
 * ERC-4337 v0.7 Paymaster（ガス代代払い）連携。
 *
 * permissionless.js v0.2.x と EntryPoint v0.7 に対応する。
 *
 * Paymaster は UserOperation のガス代を肩代わりする主体であり、SDK は Paymaster サービス
 * （ERC-7677 準拠 RPC。permissionless.js v0.2.x / viem の PaymasterClient と同一のメソッド群）に
 * `pm_getPaymasterStubData` / `pm_getPaymasterData` を問い合わせて v0.7 の paymaster フィールド
 * （paymaster / paymasterData / paymasterVerificationGasLimit / paymasterPostOpGasLimit）を取得し、
 * UserOperation に付与する。
 *
 * `PaymasterClient` seam を介してのみ Paymaster サービスに触れる（bundler.ts の `BundlerRpc` と同方針の
 * DI）。既定実装は fetch-adapter.ts の `createFetchPaymasterClient` が提供し、テストは fake な
 * `PaymasterClient` を注入して実 RPC 非依存でスポンサーフローを検証できる。
 *
 * スポンサーフローは 2 段階で行う（ERC-7677 の標準手順）:
 *   1. スタブ取得（`getPaymasterStubData`）: ガス見積もりに使う仮の paymaster フィールドを得る。
 *      これを付与した UserOp で Bundler の `eth_estimateUserOperationGas` を実行する。
 *   2. 本取得（`getPaymasterData`）: 見積もり済みのガスを反映した UserOp で最終的な署名付き
 *      paymaster フィールドを得て付与する。
 *
 * セキュリティ上の注意:
 * - Paymaster URL・UserOp フィールド・エラー本文を例外 message / context / cause に伝播させない。
 *   トランスポート / レスポンス形状失敗は VericertsError（code `1021`、retriable）、
 *   Paymaster が返す JSON-RPC error（Sponsorship 拒否）は code `7003` PAYMASTER_REJECTED に正規化する（paymaster-fetch-adapter.ts）。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { assertGasWithinLimits } from './gas-limits.js';
import { fromHex } from './hex.js';
import type { Hex, UserOperationV07 } from './types.js';
import { withUserOperationFields } from './user-operation.js';

/**
 * Paymaster が返す v0.7 の gas 代払いフィールド群。
 *
 * `paymaster` は Paymaster コントラクトアドレス、`paymasterData` はその検証に使う追加データ。
 * gas 上限は Paymaster が算出して返す場合がある（未指定時は呼び出し側の既定にフォールバック）。
 */
export interface PaymasterFields {
  /** Paymaster コントラクトアドレス。 */
  readonly paymaster: Hex;
  /** Paymaster に渡す追加データ（署名等）。 */
  readonly paymasterData: Hex;
  /** Paymaster 検証フェーズのガス上限（Paymaster が算出する場合のみ）。 */
  readonly paymasterVerificationGasLimit?: bigint;
  /** Paymaster 実行後（postOp）フェーズのガス上限（Paymaster が算出する場合のみ）。 */
  readonly paymasterPostOpGasLimit?: bigint;
}

/**
 * Paymaster サービスへのアクセス seam。paymaster.ts はこのインターフェース経由でのみ
 * Paymaster サービスに触れる。既定実装は fetch-adapter.ts の `createFetchPaymasterClient`。
 *
 * viem / permissionless.js v0.2.x の PaymasterClient と同じ 2 メソッドを持つ。
 */
export interface PaymasterClient {
  /**
   * ガス見積もり用の仮 paymaster フィールド（スタブ）を取得する（`pm_getPaymasterStubData`）。
   *
   * @param userOp スタブ取得対象の UserOperation（ガスは未見積もりでよい）。
   * @param chainId 対象チェーン ID。
   * @returns 仮の paymaster フィールド。
   * @throws RPC / トランスポート失敗の場合（VericertsError、code `1021`）。
   */
  getPaymasterStubData(userOp: UserOperationV07, chainId: number): Promise<PaymasterFields>;
  /**
   * 見積もり反映後の最終 paymaster フィールドを取得する（`pm_getPaymasterData`）。
   *
   * @param userOp ガス見積もりを反映済みの UserOperation。
   * @param chainId 対象チェーン ID。
   * @returns 最終的な paymaster フィールド。
   * @throws RPC / トランスポート失敗の場合（VericertsError、code `1021`）。
   */
  getPaymasterData(userOp: UserOperationV07, chainId: number): Promise<PaymasterFields>;
}

/**
 * UserOperation に Paymaster フィールドを付与した複製を返す。
 *
 * `paymasterVerificationGasLimit` / `paymasterPostOpGasLimit` を Paymaster が返さなかった場合は
 * 元の UserOp の値を保持する（見積もりで別途埋める運用のため上書きしない）。
 *
 * @param userOp 元の UserOperation。
 * @param fields 付与する Paymaster フィールド。
 * @returns paymaster フィールドを付与した新しい UserOperationV07。
 */
export function applyPaymasterFields(
  userOp: UserOperationV07,
  fields: PaymasterFields,
): UserOperationV07 {
  // seam の実装（`PaymasterClient`）が `normalizePaymasterFields` を通さない場合でも、巨大な
  // paymaster ガス値が署名対象へ入らないよう適用時にも上限を検査する。
  assertGasWithinLimits(fields);
  return withUserOperationFields(userOp, {
    paymaster: fields.paymaster,
    paymasterData: fields.paymasterData,
    paymasterVerificationGasLimit:
      fields.paymasterVerificationGasLimit ??
      ownProperty<bigint>(userOp, 'paymasterVerificationGasLimit'),
    paymasterPostOpGasLimit:
      fields.paymasterPostOpGasLimit ?? ownProperty<bigint>(userOp, 'paymasterPostOpGasLimit'),
  });
}

/**
 * スポンサーフローの段階を選ぶオプション。
 */
export interface SponsorUserOperationOptions {
  /**
   * `true` のときスタブ（`getPaymasterStubData`）を取得する（ガス見積もり前段）。
   * `false`（既定）のとき本データ（`getPaymasterData`）を取得する（見積もり反映後）。
   */
  readonly stub?: boolean;
}

/**
 * Paymaster にガス代払いを依頼し、paymaster フィールドを付与した UserOperation を返す。
 *
 * `options.stub === true` のときはガス見積もり用のスタブを、そうでなければ見積もり反映後の
 * 最終データを取得して付与する。ネットワークアクセスは `PaymasterClient` seam に委譲するため、
 * fake seam の注入で単体テスト可能。
 *
 * @param client Paymaster サービスの seam。
 * @param userOp スポンサー対象の UserOperation。
 * @param chainId 対象チェーン ID。
 * @param options スタブ / 本データの選択。
 * @returns paymaster フィールドを付与した UserOperationV07。
 * @throws RPC / トランスポート失敗の場合（VericertsError、code `1021`）。
 */
export async function sponsorUserOperation(
  client: PaymasterClient,
  userOp: UserOperationV07,
  chainId: number,
  options: SponsorUserOperationOptions = {},
): Promise<UserOperationV07> {
  const fields = ownProperty<boolean>(options, 'stub')
    ? await client.getPaymasterStubData(userOp, chainId)
    : await client.getPaymasterData(userOp, chainId);
  return applyPaymasterFields(userOp, fields);
}

/** Paymaster サービスの標準メソッド名（ERC-7677）。 */
export const PAYMASTER_METHOD_STUB = 'pm_getPaymasterStubData';
export const PAYMASTER_METHOD_DATA = 'pm_getPaymasterData';

/** `paymaster`: 0x + 20 バイト（40 hex）のアドレス。 */
const PAYMASTER_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
/** `paymasterData`: 0x + 偶数桁の hex（空データ `0x` を含む）。 */
const PAYMASTER_DATA_PATTERN = /^0x(?:[0-9a-fA-F]{2})*$/;

/** unknown から `PaymasterFields` を正規化する。不正値（形状不正の hex / アドレス含む）は 1021 に正規化する。 */
export function normalizePaymasterFields(result: unknown): PaymasterFields {
  if (result === null || typeof result !== 'object') {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  const r = result as Record<string, unknown>;
  // `paymasterAndData` は paymaster(20B) || gas limits || paymasterData と連結されるため、短い・非 hex・
  // 奇数長の値はバイト境界をずらし、EntryPoint が解釈する paymaster / ガス上限が意図と変わる。
  // 署名対象に載せる前に境界で形状を保証する。
  if (
    typeof r.paymaster !== 'string' ||
    !PAYMASTER_ADDRESS_PATTERN.test(r.paymaster) ||
    typeof r.paymasterData !== 'string' ||
    !PAYMASTER_DATA_PATTERN.test(r.paymasterData)
  ) {
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
  const fields: PaymasterFields = {
    paymaster: r.paymaster as Hex,
    paymasterData: r.paymasterData as Hex,
    ...(r.paymasterVerificationGasLimit !== undefined
      ? { paymasterVerificationGasLimit: fromHex(r.paymasterVerificationGasLimit) }
      : {}),
    ...(r.paymasterPostOpGasLimit !== undefined
      ? { paymasterPostOpGasLimit: fromHex(r.paymasterPostOpGasLimit) }
      : {}),
  };
  // Paymaster 応答のガス値も署名対象に入る外部入力。巨大値は署名前に拒否する。
  assertGasWithinLimits(fields);
  return fields;
}
