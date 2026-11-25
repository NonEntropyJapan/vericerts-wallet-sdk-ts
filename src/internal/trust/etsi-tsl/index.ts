/**
 * trust/etsi-tsl モジュールの公開エントリ。
 *
 * ETSI TS 119 612 Trusted List の取得（LOTL/TSL）・XMLDSig 検証・Qualified Certificate チェーン
 * 検証プリミティブと永続キャッシュの型（`TrustedListCache` /
 * `QualifiedTspEntry`）とそのキャッシュ層を再エクスポートする。facade（wallet.ts / index.ts）
 * への配線（`loadTrustedList` / `verifyQualifiedCertificate` の wallet メソッド化、キャッシュ層の
 * 実配線）は統合担当（trust/arf 以降）が行う。
 */

export {
  type BuildTrustedListCacheEntryInput,
  buildTrustedListCacheEntry,
  createTrustedListCache,
  readTrustedListCache,
  storeTrustedListCache,
  TRUSTED_LIST_CACHE_MAX_TTL_SECONDS,
  type TrustedListCache,
} from './cache.js';
export {
  type CertChainResult,
  MAX_INTERMEDIATES,
  type VerifyChainOptions,
  verifyCertificateChain,
} from './chain.js';
export {
  type LoadTrustedListOptions,
  type LoadTrustedListResult,
  loadTrustedList,
  type TrustedListFetcher,
  type TrustedListKind,
  type VerifyQualifiedCertificateOptions,
  verifyQualifiedCertificate,
} from './etsi-tsl.js';
export {
  type ExtractQtspOptions,
  extractNextUpdate,
  extractQtspCertificates,
  extractQualifiedTspEntries,
  extractTslPointers,
  grantedTrustAnchors,
  type QtspServiceCertificate,
  type QualifiedTspEntry,
  type TslPointer,
} from './tsl.js';
export {
  type CertSignatureAlg,
  derEquals,
  type ParsedCertificate,
  parseCertificate,
} from './x509.js';
export { verifyXmlDsig, type XmlDsigResult } from './xml/xmldsig.js';
