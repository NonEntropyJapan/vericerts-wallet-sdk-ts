/**
 * trust/rp-access モジュールの公開エントリ。
 *
 * ETSI TS 119 475 の RP Access Certificate パース・権限マッチング・TSL 連携検証プリミティブを
 * 再エクスポートする。facade（wallet.ts）への `verifyRpAccessCertificate` メソッド配線は統合担当が
 * 行う（etsi-tsl と同方針）。
 */

export {
  allClaimsAuthorized,
  authorizeClaims,
  isCrossBorder,
} from './authorization.js';
export {
  createRpCertJudgmentCache,
  RP_CERT_JUDGMENT_CACHE_TTL_SECONDS,
  readRpCertJudgment,
  rpCertJudgmentCacheKey,
  storeRpCertJudgment,
} from './cache.js';
export {
  type ParsedRpAccessCertificate,
  parseRpAccessCertificate,
  RP_ACCESS_ATTR_OIDS,
  type RpAuthorizedScope,
  type RpIdentity,
} from './cert.js';
export type {
  ClaimAuthorization,
  RequestedClaim,
  RevocationMethod,
  RevocationStatus,
  RpAccessVerificationResult,
  RpClaimCategory,
  RpDescriptor,
  TrustChainNode,
  TrustSource,
} from './types.js';
export {
  type VerifyRpAccessOptions,
  verifyRpAccessCertificate,
} from './verify.js';
