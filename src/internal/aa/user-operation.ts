/**
 * ERC-4337 v0.7 UserOperation の構築と UserOpHash 計算。
 *
 * `buildUserOperation` は sender / nonce / callData と任意フィールドから、Bundler 送信可能な
 * 完全な `UserOperationV07` を組み立てる（欠落したガス・fee はゼロ埋めし、`estimateUserOperationGas`
 * / fee 補完で埋める運用を想定）。`getUserOpHash` は viem の `getUserOperationHash`（EntryPoint v0.7
 * 準拠 / permissionless.js v0.2.x が内部で使用するのと同一実装）で決定論的な hash を計算する。
 *
 * ネットワークには一切触れない純粋関数であり、単体テスト可能。Bundler 通信は bundler.ts が担う。
 *
 * セキュリティ上の注意:
 * - アドレス・calldata・署名などの入力を例外 message / context / cause に伝播させない。
 *   viem 由来例外は cause を渡さず正規化する。
 */

import { getUserOperationHash } from 'viem/account-abstraction';
import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { ENTRY_POINT_V07_ADDRESS, type Hex, type UserOperationV07 } from './types.js';

/** ゼロ署名（未署名の UserOp のプレースホルダ。ガス見積もり時に使用）。 */
export const EMPTY_SIGNATURE: Hex = '0x';

/** 空 calldata。 */
const EMPTY_HEX: Hex = '0x';

/**
 * `buildUserOperation` の入力。ガス・fee フィールドは任意で、未指定は 0n（見積もり前）とする。
 */
export interface BuildUserOperationInput {
  /** 送信元スマートアカウントアドレス。 */
  readonly sender: Hex;
  /** アカウントの nonce（EntryPoint から取得済みの値）。 */
  readonly nonce: bigint;
  /** アカウントに実行させる calldata。 */
  readonly callData: Hex;
  /** 未デプロイ時の Factory アドレス（デプロイ済みは省略）。 */
  readonly factory?: Hex;
  /** Factory 呼び出しの calldata（factory とセット）。 */
  readonly factoryData?: Hex;
  /** 実行ガス上限（未指定は 0n）。 */
  readonly callGasLimit?: bigint;
  /** 検証ガス上限（未指定は 0n）。 */
  readonly verificationGasLimit?: bigint;
  /** 事前検証ガス（未指定は 0n）。 */
  readonly preVerificationGas?: bigint;
  /** 最大ガス価格（未指定は 0n）。 */
  readonly maxFeePerGas?: bigint;
  /** 最大 priority fee（未指定は 0n）。 */
  readonly maxPriorityFeePerGas?: bigint;
  /** Validator 署名（未指定は EMPTY_SIGNATURE。呼び出し側が UserOpHash 署名後に設定）。 */
  readonly signature?: Hex;
}

/**
 * 入力から完全な v0.7 UserOperation を構築する。
 *
 * `factory` と `factoryData` は一方のみ指定を不正とする（両方指定または両方省略のみ許可）。
 * ガス・fee の未指定フィールドは 0n で埋め、後段の見積もり・fee 補完で上書きする運用を前提とする。
 *
 * @param input sender / nonce / callData と任意の factory・ガス・署名。
 * @returns 構築済み UserOperationV07。
 * @throws factory / factoryData の片側のみ指定など不整合の場合（VericertsError、code `4070`）。
 */
export function buildUserOperation(input: BuildUserOperationInput): UserOperationV07 {
  // 任意プロパティは自身のプロパティに限って読む。ここで組み立てた
  // UserOperation はそのまま `getUserOpHash` でハッシュされ Validator が署名する対象になる。
  // 継承値を拾うと、これらを**省略した**正当な組み立てでも攻撃者の `callData`（＝実行される
  // 呼び出し）・ガス / 手数料・`signature` が署名対象へ入る。
  const factory = ownProperty<Hex>(input, 'factory');
  const factoryData = ownProperty<Hex>(input, 'factoryData');
  if ((factory !== undefined) !== (factoryData !== undefined)) {
    // factory とデプロイ用 calldata は必ずセットで指定する。
    throw new VericertsError(ErrorCodes.INVALID_EVM_ADDRESS);
  }
  return {
    sender: input.sender,
    nonce: input.nonce,
    factory,
    factoryData,
    callData: ownProperty<Hex>(input, 'callData') ?? EMPTY_HEX,
    callGasLimit: ownProperty<bigint>(input, 'callGasLimit') ?? 0n,
    verificationGasLimit: ownProperty<bigint>(input, 'verificationGasLimit') ?? 0n,
    preVerificationGas: ownProperty<bigint>(input, 'preVerificationGas') ?? 0n,
    maxFeePerGas: ownProperty<bigint>(input, 'maxFeePerGas') ?? 0n,
    maxPriorityFeePerGas: ownProperty<bigint>(input, 'maxPriorityFeePerGas') ?? 0n,
    signature: ownProperty<Hex>(input, 'signature') ?? EMPTY_SIGNATURE,
  };
}

/**
 * UserOperation を新しいフィールドで上書きした複製を返す（ガス見積もり結果・署名の反映用）。
 *
 * @param userOp 元の UserOperation。
 * @param patch 上書きするフィールド。
 * @returns 上書き済みの新しい UserOperationV07。
 */
export function withUserOperationFields(
  userOp: UserOperationV07,
  patch: Partial<UserOperationV07>,
): UserOperationV07 {
  return { ...userOp, ...patch };
}

/**
 * UserOpHash を計算する（EntryPoint v0.7 / chainId バインド）。
 *
 * viem の `getUserOperationHash`（permissionless.js v0.2.x が内部で用いるのと同一の EntryPoint v0.7
 * 準拠実装）を使用する。UserOpHash は Validator が署名する対象であり、chainId と EntryPoint
 * アドレスにバインドされる（リプレイ防止）。
 * viem は任意フィールド（paymaster / factory / authorization 等）を分割代入で読むため、own の
 * 列挙プロパティだけを null プロトタイプへ写してから渡し、継承値をハッシュへ入れない。
 * UserOperation はアクセサを含まないプレーンデータを想定する。
 *
 * @param userOp 対象 UserOperation（署名フィールドは hash に含まれない）。
 * @param chainId 対象チェーン ID。
 * @returns UserOpHash（32 バイト、`0x` プレフィックス付き hex）。
 * @throws hash 計算に失敗した場合（VericertsError、code `1021`）。入力値は例外に含めない。
 */
export function getUserOpHash(userOp: UserOperationV07, chainId: number): Hex {
  try {
    const ownUserOp = Object.assign(Object.create(null) as object, userOp);
    return getUserOperationHash({
      chainId,
      entryPointAddress: ENTRY_POINT_V07_ADDRESS,
      entryPointVersion: '0.7',
      userOperation: ownUserOp,
    });
  } catch {
    // viem 由来例外にはアドレス・calldata が含まれ得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
  }
}
