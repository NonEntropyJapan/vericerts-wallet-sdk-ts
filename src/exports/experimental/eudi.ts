/** EUDI 受領・提示の実験的な公開 API。警告ラップは `../experimental.ts` の実体を共有する。 */

export type { ReceiveDeps } from '../../internal/auth/eudi/issuance/types.js';
export type { PresentDeps, PresentOptions } from '../../internal/auth/eudi/presentation/types.js';
export type { JarTrustOptions } from '../../internal/auth/jar/index.js';
export type { SubmitFetchLike } from '../../internal/auth/oid4vp/oid4vp-submit.js';
export type { CredentialSigner } from '../../internal/credential/vc/signer.js';
export type {
  AttestationCatalogueSource,
  EAACredential,
  PIDAttributeName,
  PIDCredential,
  VerifyReceivedAttestation,
} from '../../internal/eudi/pid/index.js';
export type { ClientAttestation } from '../../internal/eudi/wua/types.js';
export type { FetchLike } from '../../internal/fetch-di.js';
export type { Metrics } from '../../internal/observability/metrics.js';
export type { ReceivedIssuerTrust } from '../../wallet/issuer-trust/index.js';

export {
  presentEAACredential,
  presentPIDCredential,
  receiveVerifiedEAA,
  receiveVerifiedPID,
} from '../experimental.js';
