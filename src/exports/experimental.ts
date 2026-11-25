/**
 * `@experimental` 公開 API のサブパスバレル（`vericerts-wallet-sdk/experimental`）。
 *
 * このサブパスの API は minor リリースで挙動やシグネチャが変わり得る。
 * メインエントリからは再エクスポートしない。型と定数は利用時に警告を出せないため、
 * 実験的な API であることを import 元のサブパスで示す。
 *
 * 関数とクラスは公開時に `markExperimental` でラップする。利用者が呼び出すか
 * インスタンス化したときに、API 名ごとに初回だけ警告する。SDK 内部からの直接呼び出しは
 * 警告を出さない。非推奨の API には `markDeprecated` を使い、代替 API を案内する。
 */

import { fetchIssuerMetadata as fetchIssuerMetadataImpl } from '../internal/auth/eudi/issuance/metadata.js';
import {
  presentEAACredential as presentEAACredentialImpl,
  presentPIDCredential as presentPIDCredentialImpl,
} from '../internal/auth/eudi/presentation/present.js';
import {
  assertBinding as assertBindingImpl,
  assertBindingMatches as assertBindingMatchesImpl,
  bindingValueOf as bindingValueOfImpl,
  buildAuthorizationUrl as buildAuthorizationUrlImpl,
  contextKeyFrom as contextKeyFromImpl,
  contextKeyOf as contextKeyOfImpl,
  entryKeyFrom as entryKeyFromImpl,
  entryKeyOf as entryKeyOfImpl,
  fetchAuthorizationServerMetadata as fetchAuthorizationServerMetadataImpl,
  pushAuthorizationRequestForPresentation as pushAuthorizationRequestForPresentationImpl,
  pushAuthorizationRequest as pushAuthorizationRequestImpl,
  receiveCredential as receiveCredentialImpl,
  receiveCredentialViaAuthorizationCode as receiveCredentialViaAuthorizationCodeImpl,
  resolveBinding as resolveBindingImpl,
  verifyJarSignature as verifyJarSignatureImpl,
} from '../internal/auth/index.js';
import {
  buildDerivedCredential as buildDerivedCredentialImpl,
  ChainVerificationCache as ChainVerificationCacheImpl,
  checkTermsOfUse as checkTermsOfUseImpl,
  interpretEvidence as interpretEvidenceImpl,
  validateTermsOfUseOnPresentation as validateTermsOfUseOnPresentationImpl,
  verifyCredentialChain as verifyCredentialChainImpl,
  verifyCredentialChainOnPresentation as verifyCredentialChainOnPresentationImpl,
  verifyEvidence as verifyEvidenceImpl,
} from '../internal/credential/index.js';
import {
  buildClientAttestation as buildClientAttestationImpl,
  buildWuaProofOfPossession as buildWuaProofOfPossessionImpl,
  isWalletAttestationExpired as isWalletAttestationExpiredImpl,
  obtainWalletUnitAttestation as obtainWalletUnitAttestationImpl,
  parseWalletUnitAttestation as parseWalletUnitAttestationImpl,
  refreshWalletAttestation as refreshWalletAttestationImpl,
  verifyWalletUnitAttestation as verifyWalletUnitAttestationImpl,
  verifyWscdBinding as verifyWscdBindingImpl,
} from '../internal/eudi/wua/index.js';
import { markDeprecated, markExperimental } from '../internal/experimental-warning.js';
import {
  receiveVerifiedEAA as receiveVerifiedEAAImpl,
  receiveVerifiedPID as receiveVerifiedPIDImpl,
} from '../wallet/eudi/verified-receive.js';

export type { IssuerEndpoints } from '../internal/auth/eudi/issuance/metadata.js';
export type { ReceiveDeps } from '../internal/auth/eudi/issuance/types.js';
/** `presentPID` で EUDI PID を提示する際のオプション。 */
export type { PresentOptions } from '../internal/auth/eudi/presentation/index.js';
export type { PresentDeps } from '../internal/auth/eudi/presentation/types.js';
/**
 * `receiveCredential` と認可フローで使用する型。
 *
 * 受領と発行で共通の `VCFormat` は、メインバレル
 * （`exports/issuer.ts`）が唯一の公開元である。両サブパスから同名を出すと、利用者から見て
 * 同じ名前が 2 つの安定性区分（`@stable` と `@experimental`）を持つことになる。
 */
export type {
  AuthorizationCodeEndpoints,
  AuthorizationCodeFlowDeps,
  AuthorizationCodeFlowOptions,
  AuthorizationRedirect,
  AuthorizationServerEndpoints,
  FetchJarOptions,
  JarTrustOptions,
  OAuth2AuthzDetails,
  OID4VPPARRequest,
  OID4VPPARResponse,
  PARRequest,
  PARResponse,
  PresentationRequestOptions,
  ReceiveCredentialDeps,
  ReceivedVerifiableCredential,
} from '../internal/auth/index.js';
/**
 * 呼び出し点を持たない定数は警告できないためそのまま再エクスポートする。
 * サブパスに置くこと自体が `@experimental` の告知になる。
 */
export { DEFAULT_TTL_MS_BY_FLOW } from '../internal/auth/index.js';
export type {
  ClientAttestation,
  ObtainWalletAttestationOptions,
  WalletUnitAttestation,
  WuaClaims,
  WuaConfirmation,
  WuaPopClaims,
  WuaPopOptions,
} from '../internal/eudi/wua/index.js';
export { WUA_CLIENT_ASSERTION_TYPE, WUA_VCT } from '../internal/eudi/wua/index.js';

/** 用途別 experimental entry はこの Proxy を再公開し、警告状態を共有する。 */
export const presentEAACredential = markExperimental(
  'presentEAACredential',
  presentEAACredentialImpl,
);
export const presentPIDCredential = markExperimental(
  'presentPIDCredential',
  presentPIDCredentialImpl,
);
export const receiveVerifiedEAA = markExperimental('receiveVerifiedEAA', receiveVerifiedEAAImpl);
export const receiveVerifiedPID = markExperimental('receiveVerifiedPID', receiveVerifiedPIDImpl);
export const fetchIssuerMetadata = markExperimental('fetchIssuerMetadata', fetchIssuerMetadataImpl);

/** 元のクレデンシャルから派生クレデンシャルを構築する。 */
export const buildDerivedCredential = markExperimental(
  'buildDerivedCredential',
  buildDerivedCredentialImpl,
);
/**
 * クラスは値と型の 2 つの名前を公開するため、型は `InstanceType` で明示的に維持する。
 * `const` だけにすると利用者の `let cache: ChainVerificationCache` が型として解決できなくなる。
 */
export type ChainVerificationCache = InstanceType<typeof ChainVerificationCacheImpl>;
export const ChainVerificationCache = markExperimental(
  'ChainVerificationCache',
  ChainVerificationCacheImpl,
);
export const checkTermsOfUse = markExperimental('checkTermsOfUse', checkTermsOfUseImpl);
export const interpretEvidence = markExperimental('interpretEvidence', interpretEvidenceImpl);
export const validateTermsOfUseOnPresentation = markExperimental(
  'validateTermsOfUseOnPresentation',
  validateTermsOfUseOnPresentationImpl,
);
export const verifyCredentialChain = markExperimental(
  'verifyCredentialChain',
  verifyCredentialChainImpl,
);
export const verifyCredentialChainOnPresentation = markExperimental(
  'verifyCredentialChainOnPresentation',
  verifyCredentialChainOnPresentationImpl,
);
export const verifyEvidence = markExperimental('verifyEvidence', verifyEvidenceImpl);

/** nonce のバインディングを検査する。 */
export const assertBinding = markExperimental('assertBinding', assertBindingImpl);
export const assertBindingMatches = markExperimental(
  'assertBindingMatches',
  assertBindingMatchesImpl,
);
export const bindingValueOf = markExperimental('bindingValueOf', bindingValueOfImpl);
export const buildAuthorizationUrl = markExperimental(
  'buildAuthorizationUrl',
  buildAuthorizationUrlImpl,
);
export const contextKeyFrom = markExperimental('contextKeyFrom', contextKeyFromImpl);
export const contextKeyOf = markExperimental('contextKeyOf', contextKeyOfImpl);
export const entryKeyFrom = markExperimental('entryKeyFrom', entryKeyFromImpl);
export const entryKeyOf = markExperimental('entryKeyOf', entryKeyOfImpl);
/**
 * 取得済みの JAR Request Object（コンパクト JWS）の署名と発行者同一性を検証する。
 *
 * `parseJarRequest`（メインバレル）は**署名を検証しない**解析専用の関数である。取得を自前で
 * 行う場合は、この関数で署名と発行者を検証してから `parseJarRequest` に渡す。
 * 取得も SDK に任せられる場合は `fetchJAR` を使う（取得と検証が 1 本になる）。
 */
export const verifyJarSignature = markExperimental('verifyJarSignature', verifyJarSignatureImpl);

export const pushAuthorizationRequest = markExperimental(
  'pushAuthorizationRequest',
  pushAuthorizationRequestImpl,
);
/**
 * OID4VP の認可要求を Verifier に push する。発行時の `pushAuthorizationRequest` とは
 * 別のリクエスト型とエラーコードを使う。
 */
export const pushAuthorizationRequestForPresentation = markExperimental(
  'pushAuthorizationRequestForPresentation',
  pushAuthorizationRequestForPresentationImpl,
);
export const receiveCredentialViaAuthorizationCode = markExperimental(
  'receiveCredentialViaAuthorizationCode',
  receiveCredentialViaAuthorizationCodeImpl,
);
/**
 * Credential Offer の URI からクレデンシャルを受領する。
 *
 * @deprecated Since v0.1.0. メインエントリの `Wallet.receiveCredential(offerURI, opts?)` に移行する。
 *   移行先のメソッドも実験的な API である。
 *   `deps` のうち `signer` / `holderDid` / `keyId` はアクティブペルソナから自動解決されるため
 *   `opts` には残りのメンバ（`authorize` / `clientId` / `redirectUri` / `txCode` /
 *   `clientAssertion*` / `format` / `createDpopProof` / `verifyReceived` / `correlationContext` /
 *   `fetchImpl`）だけを渡す。削除までの最低告知期間は 1 minor / 1 ヶ月。
 *   削除予定バージョンは確定次第 CHANGELOG の `Deprecated` 欄で告知する。
 */
export const receiveCredential = markDeprecated(
  'receiveCredential',
  receiveCredentialImpl,
  'Use `Wallet.receiveCredential(offerURI, opts)` instead.',
);
export const fetchAuthorizationServerMetadata = markExperimental(
  'fetchAuthorizationServerMetadata',
  fetchAuthorizationServerMetadataImpl,
);
export const resolveBinding = markExperimental('resolveBinding', resolveBindingImpl);

/** EUDI Wallet Unit Attestation 用のクライアントアテステーションを組み立てる。 */
export const buildClientAttestation = markExperimental(
  'buildClientAttestation',
  buildClientAttestationImpl,
);
export const buildWuaProofOfPossession = markExperimental(
  'buildWuaProofOfPossession',
  buildWuaProofOfPossessionImpl,
);
export const isWalletAttestationExpired = markExperimental(
  'isWalletAttestationExpired',
  isWalletAttestationExpiredImpl,
);
export const obtainWalletUnitAttestation = markExperimental(
  'obtainWalletUnitAttestation',
  obtainWalletUnitAttestationImpl,
);
export const parseWalletUnitAttestation = markExperimental(
  'parseWalletUnitAttestation',
  parseWalletUnitAttestationImpl,
);
export const refreshWalletAttestation = markExperimental(
  'refreshWalletAttestation',
  refreshWalletAttestationImpl,
);
export const verifyWalletUnitAttestation = markExperimental(
  'verifyWalletUnitAttestation',
  verifyWalletUnitAttestationImpl,
);
export const verifyWscdBinding = markExperimental('verifyWscdBinding', verifyWscdBindingImpl);
