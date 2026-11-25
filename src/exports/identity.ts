export {
  buildDidCoreDocument,
  buildDidWebDocument,
  createExternalKeySigner,
  type DelegatedSigner,
  importPersonaFromDid,
  inlineExternalMethods,
  type PrivateKeyJwk,
  personaKid,
  resolveDelegatedSigner,
  resolvePersonaSigner,
  samePublicKeyJwk,
  serializeDidDocument,
  signMessageJws,
  verifyHeldKeyAgainstDid,
  verifyMessageJws,
} from '../internal/credential/did-signing/index.js';
export type { DidResolverLike } from '../internal/identity/bounded-resolver.js';
// Content-addressed DID のハッシュの計算・解析・検証と、その入出力に使う型。
export type {
  ContentHashAlgorithm,
  ContentSource,
  ParsedContentHash,
} from '../internal/identity/content-hash/index.js';
export {
  computeContentHash,
  extractDidContentHash,
  parseContentHash,
  verifyContentHash,
  verifyDidContentHash,
  verifyVcContentHashClaim,
} from '../internal/identity/content-hash/index.js';
export type {
  CreateOptions,
  DIDDocument,
  DIDMethod,
  DidDocumentPatch,
  DidKeyType,
  PublicKeyJwk,
  Service,
  UpdateOptions,
  VerificationMethod,
} from '../internal/identity/did.js';
export type { ParsedDidEthr } from '../internal/identity/ethr/did-url.js';
export { parseDidEthr } from '../internal/identity/ethr/did-url.js';
export { MethodEthr, resolveDidEthr } from '../internal/identity/ethr/method-ethr.js';
export type { Erc1056EventSource } from '../internal/identity/ethr/registry.js';
export type { ParsedIpid } from '../internal/identity/ipid/did-ipid.js';
export { parseDidIpid } from '../internal/identity/ipid/did-ipid.js';
export { MethodIpid } from '../internal/identity/ipid/method-ipid.js';
export { createDidJwk, MethodJwk, resolveDidJwk } from '../internal/identity/jwk/method-jwk.js';
export type { CreateDidJwtOptions, JwtAlg } from '../internal/identity/jwt/generate.js';
export { createDidJwt } from '../internal/identity/jwt/generate.js';
export { MethodJwt, resolveDidJwt } from '../internal/identity/jwt/method-jwt.js';
export { createDidKey, MethodKey, resolveDidKey } from '../internal/identity/method-key.js';
export {
  createDidPeer0,
  createDidPeer2,
  createDidPeer4,
  MethodPeer,
  resolveDidPeer,
} from '../internal/identity/peer/method-peer.js';
export {
  createDidPkh,
  MethodPkh,
  resolveDidPkh,
} from '../internal/identity/pkh/method-pkh.js';
export type { ResolutionWorkBudget } from '../internal/identity/resolution-budget.js';
export {
  createDidResolutionResources,
  type DidResolutionResources,
} from '../internal/identity/resolution-resources/resources.js';
export { Resolver } from '../internal/identity/resolver.js';
export {
  createDidWebCache,
  DID_WEB_CACHE_MAX_TTL_SECONDS,
  type DidWebCacheEvent,
  type ResolveDidWebDeps,
} from '../internal/identity/web/did-web-cache.js';
export { didWebToUrl, MethodWeb, resolveDidWeb } from '../internal/identity/web/method-web.js';
export {
  assertWebVhCandidateVerifies,
  collectWebVhWitnessProofs,
  createDidWebVh,
  createWebVhWitnessProof,
  MethodWebVh,
  resolveDidWebVh,
  resolveDidWebVhWithMetadata,
  updateDidWebVh,
  type WebVhCollectWitnessProofsOptions,
  type WebVhDidMetadata,
  type WebVhResolution,
  type WebVhResolveOptions,
  type WebVhSignFn,
  type WebVhWitnessApprover,
  type WebVhWitnessFileItem,
  type WebVhWitnessMetadata,
  type WebVhWitnessProofSigner,
  type WebVhWitnessRequest,
} from '../internal/identity/webvh/method-webvh.js';
export type { DidNodeUrls } from '../wallet/did/did-node-urls.js';
export { createDidResolver, type DidResolverOptions } from '../wallet/did/did-resolver.js';
export { MAX_LINKED_DIDS } from '../wallet/did/linked-dids-limit.js';
