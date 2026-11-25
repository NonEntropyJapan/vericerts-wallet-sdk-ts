/**
 * credential モジュールの公開エントリ。
 *
 * JWT-VC（JWS）として W3C VC を発行・検証する最小プリミティブを再エクスポートする。
 * facade（`wallet.ts` / `index.ts`）への配線は統合担当が行う。
 */

export {
  createRemoteSigner,
  type RemoteMessageFormat,
  type RemoteSignatureFormat,
  type RemoteSignerConfig,
} from '../keymanager/jws/remote-signer.js';
export {
  newPresentationWorkBudget,
  type PresentationWorkBudget,
} from '../primitives/presentation-work-budget.js';
export {
  buildDerivedCredential,
  CHAIN_CACHE_TTL_MS,
  type ChainNode,
  type ChainPolicy,
  type ChainRelation,
  ChainVerificationCache,
  type ChainVerificationResult,
  type ChainVerifyDependencies,
  type ChainVerifyOptions,
  DEFAULT_MAX_CHAIN_DEPTH,
  type DerivedCredentialInput,
  type PresentationChainVerifyOptions,
  verifyCredentialChain,
  verifyCredentialChainOnPresentation,
} from './chain/index.js';
export {
  assertVpObject,
  checkTermsOfUse,
  type EvidenceCheck,
  type EvidenceEntry,
  type EvidenceInterpretation,
  type EvidenceVerificationResult,
  interpretEvidence,
  type LoA,
  type OdrlConstraint,
  type OdrlOperator,
  type OdrlRule,
  type TermsOfUseEntry,
  type ToUCheckOptions,
  type ToUCheckResult,
  type ToURestriction,
  type ToUViolation,
  type UnknownVocabularyPolicy,
  type UsageContext,
  type VPValidationResult,
  validateTermsOfUseOnPresentation,
  verifyEvidence,
} from './evidence-tou/index.js';
export {
  type BuildMultiFormatVPOptions,
  buildMultiFormatVP,
  type CredentialKeyBinding,
  canFulfillFormats,
  type DescriptorMapEntry,
  type EvaluateFormatCapabilityOptions,
  evaluateFormatCapability,
  type FormatCapabilityResult,
  type FormatConstraint,
  type FormatCoverage,
  type FormatDescriptor,
  isSelectiveDisclosureCapable,
  type LimitDisclosure,
  MAX_MULTI_FORMAT_COUNT,
  type MultiFormatAuditEntry,
  type MultiFormatPresentationSubmission,
  type MultiFormatVPToken,
  type NegotiableCredential,
  PRIVACY_TIER,
  SELECTIVE_DISCLOSURE_FORMATS,
  type SelectBestVCOptions,
  selectBestVC,
  type VCFormat,
  type VCSelection,
  type VpFormatRequirement,
} from './format-negotiation/index.js';
export {
  assertSigningKeyNotRevoked,
  type IssuerTrustOption,
} from './issuer-key-revocation.js';
export {
  type JsonSchema,
  type SchemaError,
  type SchemaFailSafeResult,
  type SchemaValidationResult,
  validateAgainstSchema,
} from './json-schema/index.js';
export {
  type ApplicationResult,
  type BuildApplicationOptions,
  buildCredentialApplication,
  type CredentialApplication,
  type CredentialManifest,
  type DisplayMapping,
  type FormatRequirement,
  fetchCredentialManifest,
  type ManifestAnswers,
  type ManifestDependencies,
  type ManifestIssuer,
  type ManifestStyle,
  type OutputDescriptor,
  type PresentationDefinition,
  type PresentationSubmission,
  type PresentationSubmissionDescriptor,
  parseCredentialManifest,
  processCredentialResponse,
  type SubmitApplicationDependencies,
  submitCredentialApplication,
} from './manifest/index.js';
export * from './notification/index.js';
export {
  type EmbeddedCredentialEntry,
  type EmbeddedCredentialKeyRequest,
  type EmbeddedCredentialKeyResolver,
  type EmbeddedCredentialVerifyInput,
  type PresentationVerificationFields,
  resolvePresentationVerificationFields,
  type VerificationResult,
  verifyEmbeddedCredentials,
} from './presentation/credential-results.js';
export {
  type IssuePresentationOptions,
  issuePresentation,
  issuePresentationAsync,
} from './presentation/issue.js';
export {
  type PresentationVerifierKey,
  type VerifiedPresentation,
  type VerifyPresentationOptions,
  verifyPresentation,
} from './presentation/presentation.js';
export {
  type AssertedVerifiableCredential,
  assertVerifiableCredential,
  parseVerifiableCredential,
  serializeVerifiableCredential,
} from './presentation/vc-assert.js';
export type {
  EmbeddedCredentialVerificationFields,
  EmbeddedCredentialVerificationResult,
  PresentationVerificationResult,
  ValidEmbeddedCredentialVerificationResult,
  VerifiedPresentationEnvelope,
} from './presentation/verification-result.js';
export {
  type AssertedVerifiablePresentation,
  assertVcV2Context,
  assertVerifiablePresentation,
  parseVerifiablePresentation,
  serializeVerifiablePresentation,
  VC_TYPE,
  VC_V2_CONTEXT,
  type VerifiablePresentation,
  VP_TYPE,
} from './presentation/vp.js';
export {
  DEFAULT_REFRESH_THRESHOLD_DAYS,
  type RefreshDependencies,
  type RefreshOptions,
  type RefreshPolicy,
  type RefreshResult,
  refreshCredential,
  shouldRefresh,
} from './refresh/refresh.js';
export {
  type CreateSchemaValidatorOptions,
  createSchemaValidator,
  detectSchemaValidationRoute,
  type RoutedSchemaValidationOptions,
  type RoutedSchemaValidationResult,
  type SchemaValidatableCredential,
  type SchemaValidationRoute,
  type SchemaValidator,
  type SharedSchemaValidationOptions,
  validateClaimsAgainstSchema,
} from './schema-validation/index.js';
export {
  type Disclosure,
  decodeDisclosure,
  disclosureDigest,
  encodeDisclosure,
} from './sdjwt/disclosure.js';
export {
  type AttachKeyBindingOptions,
  attachKeyBinding,
  attachKeyBindingSignature,
  createKeyBindingTemplate,
  KB_JWT_TYP,
  type KeyBindingHeader,
  type KeyBindingOptions,
  type KeyBindingPayload,
  type KeyBindingTemplate,
  type KeyBindingTemplateOptions,
} from './sdjwt/key-binding.js';
export {
  type ConfirmationClaim,
  type CreateSdJwtOptions,
  createSdJwt,
  createSdJwtAsync,
  parseSdJwt,
  type SdJwtParts,
  type StatusReference,
  selectDisclosures,
} from './sdjwt/sdjwt.js';
export {
  resolveStatus,
  type StatusCheckResult,
  type StatusListResolver,
} from './sdjwt/status.js';
export {
  ACCEPTED_SD_JWT_VC_TYPS,
  SD_JWT_VC_TYP,
  SD_JWT_VC_TYP_LEGACY,
  type SdJwtVcTyp,
} from './sdjwt/typ.js';
export {
  MAX_EXTENDS_DEPTH,
  type ResolvedTypeMetadata,
  type ResolveTypeMetadataOptions,
  resolveTypeMetadata,
  type SdJwtTypeMetadata,
  TYPE_METADATA_CACHE_TTL_MS,
  TypeMetadataCache,
  type TypeMetadataDependencies,
  type TypeMetadataValidationResult,
  validateClaimsAgainstTypeMetadata,
} from './sdjwt/type-metadata/index.js';
export {
  addKeyBinding,
  type VerifiedSdJwt,
  type VerifySdJwtOptions,
  verifySdJwt,
} from './sdjwt/verify.js';
export { CLOCK_SKEW_PROFILE, type ClockSkewKind } from './time-claims.js';
export {
  CREDENTIAL_SCHEMA_CACHE_TTL_MS,
  CredentialSchemaCache,
  JSON_SCHEMA_CREDENTIAL_TYPES,
  resolveSchemaUrl,
  type ValidateCredentialSchemaOptions,
  validateClaimsAgainstCredentialSchema,
  validateCredentialSchema,
} from './vc/credential-schema/index.js';
export {
  type IssueCredentialOptions,
  issueCredential,
  issueCredentialAsync,
} from './vc/issue.js';
export type { CredentialAlg, CredentialSignerAlg } from './vc/jws.js';
export {
  type AnyCredentialSigner,
  type AsyncCredentialSigner,
  type CredentialSigner,
  createPrivateKeySigner,
} from './vc/signer.js';
export type {
  CredentialSchemaReference,
  CredentialStatus,
  RefreshServiceConfig,
  VerifiableCredential,
} from './vc/vc.js';
export type { CredentialVerificationResult } from './vc/verification-result.js';
export { didDocumentToVerifierKey, type VerifierKeyOptions } from './vc/verifier-key.js';
export {
  type CredentialVerifierKey,
  type VerifiedCredential,
  type VerifyCredentialOptions,
  verifyCredential,
} from './vc/verify.js';
export {
  type VerificationIssue,
  verificationIssueFromCode,
  verificationIssueFromVericertsError,
} from './verification-issue.js';
