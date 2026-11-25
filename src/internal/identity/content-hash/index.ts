/**
 * content-addressed DID の contentHash 検証ユーティリティの内部バレル。
 *
 * 公開 API は `src/exports/identity.ts` から re-export する。
 */

export type {
  ContentHashAlgorithm,
  ContentHashAlgorithmSpec,
} from './algorithms.js';
export { SUPPORTED_CONTENT_HASH_ALGORITHMS } from './algorithms.js';
export { extractDidContentHash } from './did-subpath.js';
export type { ParsedContentHash } from './notation.js';
export { formatContentHash, parseContentHash } from './notation.js';
export type { ContentSource } from './verify.js';
export {
  computeContentHash,
  contentHashEquals,
  verifyContentHash,
  verifyDidContentHash,
  verifyVcContentHashClaim,
} from './verify.js';
