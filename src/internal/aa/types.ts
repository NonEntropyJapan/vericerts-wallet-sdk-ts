/**
 * aa モジュール（ERC-4337 v0.7 UserOperation 構築 + Bundler 通信）の共通型。
 *
 * UserOperation の形状は EntryPoint v0.7（unpacked）に準拠する。Bundler JSON-RPC への
 * シリアライズ（hex 変換）と署名済み UserOp の送信は bundler.ts が担い、本ファイルは型のみを提供する。
 *
 * セキュリティ上の注意:
 * - Bundler URL・アドレス・calldata・署名などの入力を例外 message / context / cause に
 *   伝播させない。
 */

/**
 * ERC-4337 EntryPoint v0.7 のコントラクトアドレス（全チェーン共通の決定論的アドレス）。
 * `@vericerts/vericerts-wallet-sdk/aa` から公開する契約。
 */
export const ENTRY_POINT_V07_ADDRESS = '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as const;

/** `0x` プレフィックス付き hex 文字列。`@vericerts/vericerts-wallet-sdk/aa` から公開する契約。 */
export type Hex = `0x${string}`;

/**
 * ERC-4337 v0.7 の UserOperation（unpacked 表現）。
 *
 * EntryPoint v0.7 は on-chain では `initCode` を `factory` + `factoryData` に、gas フィールドを
 * `accountGasLimits` / `gasFees` にパックするが、SDK 上は可読性のため unpacked で保持する。UserOpHash
 * 計算は viem が内部で packed 表現へ変換して行い（user-operation.ts）、Bundler JSON-RPC 送信は
 * unpacked v0.7 スキーマの hex 表現で行う（bundler.ts）。
 * `@vericerts/vericerts-wallet-sdk/aa` から公開する契約。
 * SDK が任意の paymaster 系フィールドを読むときは、このオブジェクト自身のプロパティを使う。
 * 継承したプロパティは getter も含めて未指定として扱う。
 */
export interface UserOperationV07 {
  /** 送信元スマートアカウントアドレス（`0x` + 40 hex）。 */
  readonly sender: Hex;
  /** アカウントの nonce（EntryPoint 管理、192bit key + 64bit sequence）。 */
  readonly nonce: bigint;
  /** 未デプロイ時のみ設定するアカウント Factory アドレス（デプロイ済みは undefined）。 */
  readonly factory?: Hex;
  /** Factory 呼び出しの calldata（factory とセットで設定）。 */
  readonly factoryData?: Hex;
  /** アカウントに実行させる calldata。 */
  readonly callData: Hex;
  /** 実行フェーズのガス上限。 */
  readonly callGasLimit: bigint;
  /** 検証フェーズのガス上限。 */
  readonly verificationGasLimit: bigint;
  /** EntryPoint がバンドル前に消費する事前検証ガス。 */
  readonly preVerificationGas: bigint;
  /** EIP-1559 の最大ガス価格（wei）。 */
  readonly maxFeePerGas: bigint;
  /** EIP-1559 の最大 priority fee（wei）。 */
  readonly maxPriorityFeePerGas: bigint;
  /** Paymaster アドレス（ERC-7677 のガス代払い）。省略時は Paymaster を使わない。 */
  readonly paymaster?: Hex;
  /** Paymaster の検証ガス上限。`paymaster` 指定時に省略すると Bundler への送信では `0n` として扱う。 */
  readonly paymasterVerificationGasLimit?: bigint;
  /** Paymaster の実行後ガス上限。`paymaster` 指定時に省略すると Bundler への送信では `0n` として扱う。 */
  readonly paymasterPostOpGasLimit?: bigint;
  /** Paymaster に渡す追加データ。`paymaster` 指定時に省略すると Bundler への送信では `0x` として扱う。 */
  readonly paymasterData?: Hex;
  /**
   * Validator 署名（UserOpHash に対する署名）。呼び出し側が設定する。Passkey の場合は
   * `signUserOpWithPasskey` がこのフィールドだけを差し替えた複製を返す。
   */
  readonly signature: Hex;
}

/**
 * Bundler が `eth_estimateUserOperationGas` で返すガス見積もり。
 */
export interface UserOperationGasEstimate {
  /** 事前検証ガス。 */
  readonly preVerificationGas: bigint;
  /** 検証フェーズのガス上限。 */
  readonly verificationGasLimit: bigint;
  /** 実行フェーズのガス上限。 */
  readonly callGasLimit: bigint;
  /** Paymaster 検証ガス上限（Paymaster 使用時のみ）。 */
  readonly paymasterVerificationGasLimit?: bigint;
  /** Paymaster 実行後ガス上限（Paymaster 使用時のみ）。 */
  readonly paymasterPostOpGasLimit?: bigint;
}

/**
 * Bundler が `eth_getUserOperationReceipt` で返すレシート（必要最小フィールド）。
 */
export interface UserOperationReceipt {
  /** 対象 UserOperation の hash。 */
  readonly userOpHash: Hex;
  /** 実行成否（EntryPoint の handleOps 結果）。 */
  readonly success: boolean;
  /** 実際に消費されたガス。 */
  readonly actualGasUsed: bigint;
  /** 実際に支払われたガス代（wei）。 */
  readonly actualGasCost: bigint;
  /** 内包する L1 トランザクションハッシュ。 */
  readonly transactionHash: Hex;
}
