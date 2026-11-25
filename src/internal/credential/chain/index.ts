/**
 * Credential Chain モジュールの公開エントリ（構築 / 検証 / 失効伝搬 / キャッシュ）。
 *
 * 派生 VC の構築、VC と VP 内のチェーン検証、および検証結果のキャッシュを提供する。
 */

export { buildDerivedCredential } from './build.js';
export { ChainVerificationCache } from './cache.js';
export {
  CHAIN_CACHE_TTL_MS,
  type ChainNode,
  type ChainPolicy,
  type ChainRelation,
  type ChainVerificationResult,
  type ChainVerifyDependencies,
  type ChainVerifyOptions,
  DEFAULT_MAX_CHAIN_DEPTH,
  type DerivedCredentialInput,
  type PresentationChainVerifyOptions,
} from './types.js';
export { verifyCredentialChain, verifyCredentialChainOnPresentation } from './verify.js';
