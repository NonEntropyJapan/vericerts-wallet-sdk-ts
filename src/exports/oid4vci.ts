/**
 * 用途別 entry `@vericerts/vericerts-wallet-sdk/oid4vci`。
 *
 * - サブパス専用バレル。`index.ts` には載せない（メインバレルの公開面を変えないため）。
 * - `reuse` 定義と OID4VCI 受領用 `add` 定義・付随型を公開する。
 *   他の Issue が所有する認可コードフローなどの値は追加しない。
 */

export type {
  CredentialDefinition,
  CredentialGrants,
  CredentialOffer,
  CredentialProof,
  CredentialResponse,
  DeferredCredential,
  DpopProof,
  FetchLike,
  GenerateProofJwtOptions,
  PreAuthorizedCodeGrant,
  PreAuthorizedTokenRequest,
  ReceivedCredential,
  RequestCredentialOptions,
  RequestCredentialResult,
  TokenResponse,
  TxCode,
} from '../internal/auth/index.js';
export {
  generateProofJWT,
  PRE_AUTHORIZED_CODE_GRANT,
  parseCredentialOffer,
  requestCredential,
  requestTokenPreAuthorized,
} from '../internal/auth/index.js';
export type { DpopProofRebuilder } from '../internal/auth/oid4vci/dpop-nonce/index.js';
export type { AuthorizationCodeGrant } from '../internal/auth/oid4vci/offer/oid4vci-offer-grants.js';
export { resolveProofNonce } from '../internal/auth/oid4vci/oid4vci-proof-nonce.js';
export type {
  PreAuthorizedIssuerEndpoints,
  ResolvedTokenEndpoint,
} from '../internal/auth/oid4vci/token/oid4vci-token-endpoint.js';
export { resolvePreAuthorizedTokenEndpoint } from '../internal/auth/oid4vci/token/oid4vci-token-endpoint.js';
export type { PublicKeyJwk } from '../internal/identity/did.js';
export type {
  CredentialAlg,
  CredentialSigner,
  CredentialSignerAlg,
} from '../internal/keymanager/jws/signer-types.js';
export type { Metrics } from '../internal/observability/metrics.js';
