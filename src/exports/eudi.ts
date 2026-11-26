/**
 * `Wallet.presentPID` の第 3 引数に渡すオプション。メソッドと同じく試験提供中（`@experimental`）。
 * `PresentOptions` は `@vericerts/vericerts-wallet-sdk` と `@vericerts/vericerts-wallet-sdk/eudi` のどちらからも
 * `import type` できる。
 */
export type { PresentOptions } from '../internal/auth/eudi/presentation/index.js';
export type {
  BatchCredentialPool,
  BatchCredentialRequest,
  BatchPoolItem,
  BatchProof,
  ConsumeResult,
  CreateBatchCredentialPoolOptions,
  PurgeResult,
  RefillConfig,
  RefillDecision,
  RefillInput,
} from '../internal/eudi/batch/index.js';
export {
  BATCH_DEFAULTS,
  BatchCredentialPoolStore,
  buildBatchCredentialRequest,
  consumeCredential,
  countAvailable,
  evaluateRefill,
  purgeExpired,
} from '../internal/eudi/batch/index.js';
export type {
  AttestationCatalogueEntry,
  AttestationCatalogueSource,
  EAACredential,
  EAAReceiveOptions,
  PIDAttributeName,
  PIDClaims,
  PIDCredential,
  PIDEnumeratedOptionalAttributeName,
  PIDMandatoryAttributeName,
  PIDReceiveOptions,
  SchemaError,
  SchemaValidationResult,
  VerifyReceivedAttestation,
} from '../internal/eudi/pid/index.js';
export {
  createRecordCatalogueSource,
  PID_MANDATORY_ATTRIBUTES,
  PID_OPTIONAL_ATTRIBUTES,
  PID_VCT,
  resolveAttestationCatalogue,
  validatePIDClaims,
  validatePIDSchema,
} from '../internal/eudi/pid/index.js';
export type {
  PresentPseudonymOptions,
  PseudonymAttestation,
  PseudonymAttestationClaims,
  PseudonymAttestationOptions,
  PseudonymConfirmation,
  PseudonymIdToken,
  PseudonymKey,
  SiopRequest,
} from '../internal/eudi/pseudonym/index.js';
export {
  canonicalizeRpIdentifier,
  computePseudonymSubject,
  derivePseudonym,
  issuePseudonymAttestation,
  PSEUDONYM_HKDF_INFO,
  PSEUDONYM_SUBJECT_PREFIX,
  PSEUDONYM_VCT,
  presentPseudonym,
} from '../internal/eudi/pseudonym/index.js';
export type {
  TransactionDataConsentInput,
  TransactionDataConsentPayload,
  TransactionDataEntry,
  TransactionDataKeyBindingOptions,
  VerifyTransactionDataHashesOptions,
} from '../internal/eudi/transaction-data/index.js';
export {
  addKeyBindingWithTransactionData,
  buildTransactionDataConsentPayload,
  computeTransactionDataHashes,
  computeTransactionDataHashesWithAlg,
  extractTransactionData,
  recordTransactionDataConsent,
  TRANSACTION_DATA_CONSENT_LOG_TYPE,
  TRANSACTION_DATA_HASH_ALG,
  verifyTransactionDataHashes,
} from '../internal/eudi/transaction-data/index.js';
export type { FetchLike } from '../internal/fetch-di.js';
export type { DidResolverLike } from '../internal/identity/bounded-resolver.js';
export type { QtspServiceCertificate } from '../internal/trust/etsi-tsl/index.js';
export {
  buildReceivedIssuerTrust,
  type ReceivedIssuerTrust,
} from '../wallet/issuer-trust/index.js';
