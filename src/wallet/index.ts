/**
 * `wallet` モジュールの公開エントリ（barrel）。
 *
 * ファサード本体（`wallet.ts` / `factory.ts`）を薄く保つため、責務ごとのサブディレクトリ
 * （`credential/` / `delegation/` / `did/` / `eudi/` / `gdpr/`）が持つ sub-barrel と、
 * 直下の型定義モジュールをここで束ねる。`src/exports/wallet.ts` は本バレルのみを参照する。
 *
 * `presentation/` は本バレルが束ねる対象ではない内部専用のサブモジュール。
 * 詳細は `./presentation/index.ts` の JSDoc を参照。
 */

export type {
  AaApi,
  BundlerRpc,
  EmergencyRevokeOptions,
  EmergencyRevokeResult,
  RevokeReason,
} from './aa-api.js';
export type {
  CreatedPresentation,
  PresentationApi,
  ReceiveCredentialOptions,
  ReceivedVerifiableCredential,
  VerifyCredentialFacadeOptions,
  VerifyPresentationFacadeOptions,
  VerifySdJwtFacadeOptions,
} from './credential/index.js';
export type { DidApi } from './did/index.js';
export type {
  CreateDIDOptions,
  DIDConfiguration,
  DIDConfigurationVerificationResult,
  LinkedDIDResult,
  UpdateDIDOptions,
} from './did/options.js';
export type { EudiApi } from './eudi/index.js';
export { createWallet } from './factory.js';
export type { GdprApi } from './gdpr/index.js';
export type { MnemonicApi } from './mnemonic-api.js';
export type {
  Attributes,
  AttributeValue,
  Counter,
  Gauge,
  Histogram,
  ImportMnemonicOptions,
  Labels,
  LogAttributes,
  Logger,
  LogValue,
  Metrics,
  OnWarning,
  SdkWarning,
  Span,
  SpanOptions,
  Tracer,
  WalletOptions,
} from './options.js';
export type {
  ImportRecoveredWalletOptions,
  ImportRecoveredWalletResult,
  RecoveryApi,
} from './recovery-api.js';
export type { ShamirApi, ShamirRecoveryResult, ShamirSharesResult } from './shamir-api.js';
export type { CreateStatusListResolverOptions, StatusApi } from './status/index.js';
export type { Wallet, WalletKeyPair } from './types.js';
