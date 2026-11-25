/**
 * OID4VCI・OID4VP と関連する認証処理の内部エントリ。
 *
 * - OID4VCI は Credential Offer を解析し、Issuer Metadata と AS Metadata（RFC 8414）を解決して、
 *   grant に応じて Credential を取得する。Authorization Code Flow では PAR と PKCE（RFC 7636 S256）を使う。
 * - OID4VP は直接形式または JAR の提示要求を解析し、DCQL / DIF Presentation Exchange v2 で
 *   VC 候補を選定する。VP Token は `direct_post` または JWE（ECDH-ES + A256GCM）の `direct_post.jwt` で送信する。
 * - DPoP は RFC 7638 のサムプリントと RFC 9449 に従い、proof の生成（§4.2）、検証（§4.3）、
 *   アクセストークンの鍵への束縛（§6.1）を扱う。
 * - SIWE（EIP-4361）は EOA（ERC-191）とコントラクトウォレット（ERC-1271）の署名検証を扱う。
 *   nonce の生成と使用済み nonce の記録によるリプレイ検知も提供する。
 */

export {
  type CreatedPresentation,
  type CreatePresentationOptions,
  createPresentation,
  type LoaCheck,
} from './create-presentation/index.js';
export {
  type CredentialMatch,
  type DcqlClaim,
  type DcqlCredential,
  type DcqlMeta,
  type DcqlQuery,
  evaluateDcql,
  parseDcqlQuery,
  type QueryableCredential,
  SUPPORTED_DCQL_FORMATS,
} from './dcql/dcql.js';
export {
  bindAccessTokenToDpopKey,
  type CreateDpopProofOptions,
  createDpopProof,
} from './dpop/dpop.js';
export {
  computeAth,
  computeJwkThumbprint,
  DPOP_JWT_TYP,
  type DpopAlg,
  type DpopProof,
  type DpopPublicKeyJwk,
  normalizeHtu,
  toDpopPublicKeyJwk,
} from './dpop/dpop-common.js';
export {
  DPOP_SIGNATURE_BYTE_LENGTH,
  type VerifiedDpopProof,
  verifyDpopProof,
} from './dpop/dpop-verify.js';
export {
  DEFAULT_DPOP_CLOCK_SKEW_SECONDS,
  DEFAULT_DPOP_MAX_AGE_SECONDS,
  type VerifyDpopProofBaseOptions,
  type VerifyDpopProofOptions,
  type VerifyDpopProofWithAccessTokenOptions,
  type VerifyDpopProofWithoutAccessTokenOptions,
} from './dpop/dpop-verify-options.js';
export {
  type FetchJarOptions,
  fetchJAR,
  type JarTrustOptions,
  type PresentationRequestOptions,
  parsePresentationRequest,
  verifyJarSignature,
} from './jar/index.js';
export {
  buildEncryptedResponse,
  type ClientMetadata,
  type EncryptedResponsePayload,
  encryptJweCompact,
  JWE_ALG_ECDH_ES,
  JWE_ALG_ECDH_ES_A256KW,
  JWE_ENC_A256GCM,
  type JweAlg,
  type JweEnc,
  type JweEncryptParams,
  type ResponseEncryptionParams,
  resolveResponseEncryption,
  SUPPORTED_JWE_ALGS,
  SUPPORTED_JWE_ENCS,
} from './jwe/index.js';
export { matchCredentials, matchCredentialsAgainstRequest } from './match-credentials/index.js';
export {
  FORMAT_JWT_VC,
  FORMAT_JWT_VC_JSON_LD,
  FORMAT_SD_JWT_VC,
  FORMAT_SD_JWT_VC_DC,
  SD_JWT_VC_FORMATS,
  selectMatchingCredentials,
  toQueryableFromSdJwt,
  toQueryableFromVc,
} from './matcher.js';
export {
  assertBinding,
  assertBindingMatches,
  assertWellFormedNonce,
  assertWithinReplayWindow,
  type BloomFilterOptions,
  bindingValueOf,
  type CheckAndUseOptions,
  type ConsumeOneTimeCredentialOptions,
  consumeOneTimeCredential,
  contextKeyFrom,
  contextKeyOf,
  createNonceStore,
  DEFAULT_BLOOM_FALSE_POSITIVE_RATE,
  DEFAULT_MAX_ENTRIES,
  DEFAULT_SWEEP_INTERVAL_MS,
  DEFAULT_TTL_MS_BY_FLOW,
  entryKeyFrom,
  entryKeyOf,
  generateNonce,
  isWellFormedNonce,
  MemoryNonceStoreAdapter,
  MIN_NONCE_ENTROPY_BITS,
  MIN_NONCE_LENGTH,
  type NonceContext,
  type NonceEvictionReason,
  type NonceFlow,
  type NonceStore,
  type NonceStoreAdapter,
  type NonceStoreBackend,
  type NonceStoreOptions,
  type PresentationReplayGuardOptions,
  REPLAY_WINDOW_SECONDS_BY_FLOW,
  type ReplayGuardOptions,
  type ReplayWindowOptions,
  resolveBinding,
  type SeenNonceEntry,
  timingSafeEqualBytes,
  timingSafeEqualString,
  VP_NONCE_RETENTION_GRACE_MS,
  verifyPresentationWithReplayGuard,
  verifySdJwtWithReplayGuard,
  vpNonceRetentionMs,
} from './nonce/index.js';
export {
  type AuthorizationCodeEndpoints,
  type AuthorizationCodeFlowDeps,
  type AuthorizationCodeFlowOptions,
  type AuthorizationRedirect,
  receiveCredentialViaAuthorizationCode,
} from './oid4vci/authz-flow/index.js';
export {
  type ReceiveCredentialDeps,
  type ReceivedVerifiableCredential,
  receiveCredential,
  toReceivedCredential,
} from './oid4vci/facade/index.js';
export {
  type CredentialGrants,
  type CredentialOffer,
  PRE_AUTHORIZED_CODE_GRANT,
  type PreAuthorizedCodeGrant,
  parseCredentialOffer,
  type TxCode,
} from './oid4vci/offer/oid4vci-offer.js';
export type {
  CredentialDefinition,
  CredentialProof,
  CredentialResponse,
  DeferredCredential,
  FetchLike,
  GenerateProofJwtOptions,
  ReceivedCredential,
  RequestCredentialOptions,
  RequestCredentialResult,
} from './oid4vci/oid4vci.js';
export { generateProofJWT, requestCredential } from './oid4vci/oid4vci.js';
export {
  type AuthorizationServerEndpoints,
  fetchAuthorizationServerMetadata,
} from './oid4vci/oid4vci-as-metadata.js';
export { buildAuthorizationUrl } from './oid4vci/oid4vci-authz-url.js';
export { generatePkcePair, type PkcePair } from './oid4vci/oid4vci-pkce.js';
export {
  type OAuth2AuthzDetails,
  type PARRequest,
  type PARResponse,
  pushAuthorizationRequest,
} from './oid4vci/par/index.js';
export type {
  AuthorizationCodeTokenRequest,
  PreAuthorizedTokenRequest,
} from './oid4vci/token/oid4vci-token.js';
export {
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_PRE_AUTHORIZED_CODE,
  requestTokenAuthorizationCode,
  requestTokenPreAuthorized,
} from './oid4vci/token/oid4vci-token.js';
export type { TokenResponse } from './oid4vci/token/oid4vci-token-http.js';
export {
  buildVPToken,
  buildVPTokenTemplate,
  type JwtVcPresentationInput,
  type PresentationInput,
  type SdJwtPresentationInput,
  type SdJwtTemplateInput,
} from './oid4vp/oid4vp.js';
export {
  RESPONSE_MODE_DIRECT_POST,
  RESPONSE_MODE_DIRECT_POST_JWT,
  type SubmitPresentationOptions,
  submitPresentation,
} from './oid4vp/oid4vp-submit.js';
export {
  type OID4VPPARRequest,
  type OID4VPPARResponse,
  pushAuthorizationRequestForPresentation,
} from './oid4vp-par/index.js';
export {
  OID4VP_SCHEME,
  type PresentationRequest,
  parseAuthorizationRequest,
  parseJarRequest,
} from './request.js';
export {
  type EncodedTransactionData,
  PRESENTATION_REQUEST_V2_SPEC_VERSION,
  type PresentationRequestV2,
  parseTransactionDataClaim,
  parseTransactionDataQueryParam,
  toPresentationRequestV2,
} from './request-v2.js';
export {
  assertValidRPRegistration,
  type GenerateIdTokenOptions,
  generateIDToken,
  generateVpToken,
  parseSIOPv2Request,
  processSIOPv2Request,
  type RPRegistration,
  type SIOPv2Request,
  type SIOPv2Response,
  type VerifiedIdToken,
  type VerifyIdTokenOptions,
  verifyIDToken,
} from './siop/index.js';
export {
  ERC1271_MAGIC_VALUE,
  type Erc1271Rpc,
  generateSiweMessage,
  type Hex as SiweHex,
  parseSiweMessage,
  type SiweMessage,
  type SiweParams,
  type ValidateSiweOptions,
  validateSiweMessage,
} from './siwe/siwe.js';
export { createFetchErc1271Rpc, type Erc1271FetchLike } from './siwe/siwe-erc1271-adapter.js';
export { signSIWE } from './siwe/siwe-sign.js';
export { verifyEoaSignature, verifyErc1271Signature } from './siwe/siwe-verify.js';
