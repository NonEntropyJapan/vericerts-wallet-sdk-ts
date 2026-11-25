/**
 * Wallet の AA（Account Abstraction）アカウントで Validator を緊急失効させる API。
 *
 * 呼び出し側が対象のアカウントアドレス、署名鍵、ネットワーク接続先（`EvmCallSource` /
 * `BundlerRpc`）とガス価格を `opts` で指定する。EntryPoint は ERC-4337 v0.7 の
 * 決定論的シングルトンを使用する。
 */

import type { BundlerRpc } from '../internal/aa/bundler.js';
import type { EmergencyRevokeResult, RevokeReason } from '../internal/aa/emergency-revoke.js';
import type { EvmCallSource } from '../internal/asset/rpc.js';

export type { BundlerRpc } from '../internal/aa/bundler.js';
export type { EmergencyRevokeResult, RevokeReason } from '../internal/aa/emergency-revoke.js';

/** `emergencyRevokeValidator` のオプション（アカウント・署名鍵・ネットワーク接続先）。 */
export interface EmergencyRevokeOptions {
  /** 署名に使う K1 派生鍵の ID（`deriveKey` が返した `KeyPair.id`）。 */
  readonly keyId: string;
  /** 失効対象の ModularAccount アドレス。 */
  readonly accountAddress: string;
  /** `keyId` に対応する、account に install 済みの ECDSAValidator アドレス。 */
  readonly signingValidatorAddress: string;
  /** 対象チェーン ID。 */
  readonly chainId: number;
  /** ModularAccount / EntryPoint の view 呼び出し（`getValidators` / `getNonce`）。 */
  readonly callSource: EvmCallSource;
  /** UserOperation の送信・レシート取得に使う Bundler RPC。 */
  readonly bundlerRpc: BundlerRpc;
  /**
   * EIP-1559 の最大ガス価格（wei）。Bundler の gas estimate はガス上限のみを返すため、
   * 呼び出し側が現在のネットワーク fee 相場から明示的に注入する。
   */
  readonly maxFeePerGas: bigint;
  /** EIP-1559 の最大 priority fee（wei）。 */
  readonly maxPriorityFeePerGas: bigint;
  /**
   * 署名してよい最悪ケースのガス代総額（wei。Bundler 見積りの全ガス上限の合計 × `maxFeePerGas`）。
   * 上限を超える見積りは署名前に `1021` で拒否する。
   * 未指定でも各ガス値には SDK 内蔵の絶対上限が掛かる。
   */
  readonly maxTotalCostWei?: bigint;
  /** レシート未確定時のポーリング回数（既定 10）。 */
  readonly maxReceiptAttempts?: number;
  /** ポーリング間隔（ミリ秒、既定 1000）。 */
  readonly receiptPollIntervalMs?: number;
}

/** AA 緊急 Validator 失効の公開 API。 */
export interface AaApi {
  /**
   * K1 派生 ECDSA Validator の署名で、署名者自身を除く install 済み全 Validator を削除する
   * （cooldown なし）。Dashboard ログに `reason` 付きで JWS 署名レコードを追記する。
   *
   * @param reason 失効理由。
   * @param opts アカウント・署名鍵・ネットワーク接続先。
   * @throws 署名に使う Validator が install されていない場合（code `1022`）、
   *         UserOperation 送信・レシート取得・実行結果が失敗の場合（code `1021`）。
   */
  emergencyRevokeValidator(
    reason: RevokeReason,
    opts: EmergencyRevokeOptions,
  ): Promise<EmergencyRevokeResult>;
}
