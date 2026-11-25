/**
 * aa モジュール（ERC-4337 v0.7 UserOperation 構築 + Bundler 通信 + UserOpHash 計算）の
 * 内部バレル。
 *
 * permissionless.js v0.2.x と EntryPoint v0.7 を対象にする。
 *
 * - types.ts:         UserOperationV07・見積もり・レシート・EntryPoint v0.7 アドレス。
 * - user-operation.ts: UserOperation 構築・フィールド上書き・UserOpHash 計算（ネットワーク非依存）。
 * - bundler.ts:       Bundler JSON-RPC seam（BundlerRpc）と send / estimate / receipt / supportedEntryPoints。
 * - fetch-adapter.ts: fetch を隔離した BundlerRpc の既定実装（createFetchBundlerRpc）。
 * - paymaster.ts: Paymaster seam（PaymasterClient）とスポンサーフロー（sponsorUserOperation）。
 * - paymaster-fetch-adapter.ts: fetch を隔離した PaymasterClient の既定実装（createFetchPaymasterClient）。
 *
 * 署名（UserOpHash への Validator 署名）と wallet facade への配線は別スコープであり本バレルには含めない。
 *
 * - ephemeral-nonce.ts: SSO ZK proof の ephemeral signer 束縛値（id_token の nonce クレーム）
 *   生成（コントラクトの SsoSignature.ephemeralCommitment および SSO 認証回路と同一定義）。
 * - iss-sub-commitment.ts: SSO ZK proof の issSubCommitment（pub[0]）束縛値
 *   `uint256(keccak256(iss || 0x00 || sub)) % r` 生成（ZKValidator.issSubCommitment /
 *   AccountFactory.computeSalt と同一プリイメージ。griefing 占有拒否）。
 */

export type { BundlerRpc } from './bundler.js';
export {
  estimateUserOperationGas,
  getSupportedEntryPoints,
  getUserOperationReceipt,
  sendUserOperation,
  toRpcUserOperation,
} from './bundler.js';
export {
  BN254_SCALAR_FIELD,
  ephemeralNonceClaim,
  ephemeralNonceValue,
} from './ephemeral-nonce.js';
export type { FetchLike } from './fetch-adapter.js';
export { createFetchBundlerRpc } from './fetch-adapter.js';
export { issSubCommitmentClaim, issSubCommitmentValue } from './iss-sub-commitment.js';
export {
  applyPaymasterFields,
  normalizePaymasterFields,
  PAYMASTER_METHOD_DATA,
  PAYMASTER_METHOD_STUB,
  type PaymasterClient,
  type PaymasterFields,
  type SponsorUserOperationOptions,
  sponsorUserOperation,
} from './paymaster.js';
export { createFetchPaymasterClient } from './paymaster-fetch-adapter.js';
export {
  ENTRY_POINT_V07_ADDRESS,
  type Hex,
  type UserOperationGasEstimate,
  type UserOperationReceipt,
  type UserOperationV07,
} from './types.js';
export {
  type BuildUserOperationInput,
  buildUserOperation,
  EMPTY_SIGNATURE,
  getUserOpHash,
  withUserOperationFields,
} from './user-operation.js';
