/**
 * RP Access Certificate の権限マッチング（trust/rp-access）。
 *
 * ETSI TS 119 475 で証明書に載る「認可された属性 / 目的 / カテゴリ」と、RP が要求した
 * `RequestedClaim[]` を突合し、属性ごとの許可判定（ClaimAuthorization）を返す。
 * fail-closed: 認可集合に無い / 目的不一致 / カテゴリ非許可はすべて拒否する。
 */

import { ErrorCodes } from '../../errors.js';
import type { RpAuthorizedScope } from './cert.js';
import type { ClaimAuthorization, RequestedClaim } from './types.js';

/** EU / EEA の ISO 3166-1 alpha-2 コード（Cross-border 判定用）。 */
const EU_EEA_COUNTRIES: ReadonlySet<string> = new Set([
  'AT',
  'BE',
  'BG',
  'HR',
  'CY',
  'CZ',
  'DK',
  'EE',
  'FI',
  'FR',
  'DE',
  'GR',
  'HU',
  'IE',
  'IT',
  'LV',
  'LT',
  'LU',
  'MT',
  'NL',
  'PL',
  'PT',
  'RO',
  'SK',
  'SI',
  'ES',
  'SE',
  'IS',
  'LI',
  'NO',
]);

/** RP 所在国が EU / EEA 域外または不明なら Cross-border 警告対象（true）。 */
export function isCrossBorder(country: string): boolean {
  return !EU_EEA_COUNTRIES.has(country.toUpperCase());
}

/**
 * 認可集合に要求値が含まれるか。認可集合が空の場合は「制約なし」ではなく「未認可」とみなす
 * （fail-closed）。ただし purpose/category は空集合を「無制約」とする運用差があるため引数で切替える。
 */
function isAllowed(
  allowSet: readonly string[],
  requested: string,
  emptyMeansAll: boolean,
): boolean {
  if (allowSet.length === 0) {
    return emptyMeansAll;
  }
  return allowSet.includes(requested);
}

/** 1 件の要求属性を認可スコープと突合する。 */
function authorizeClaim(claim: RequestedClaim, scope: RpAuthorizedScope): ClaimAuthorization {
  const authorized = isAllowed(scope.attributes, claim.claimPath, false);
  // purpose / category は Cert が明示しない場合に「無制約」とみなす（ETSI TS 119 475 の任意拡張）。
  const purposeAligned = isAllowed(scope.purposes, claim.purpose, true);
  const categoryAllowed = isAllowed(scope.categories, claim.category, true);
  const reason = denialReason(authorized, purposeAligned, categoryAllowed);
  return {
    claimPath: claim.claimPath,
    authorized,
    purposeAligned,
    categoryAllowed,
    ...(reason !== undefined ? { reason } : {}),
  };
}

/** 拒否理由のコード文字列を決める。すべて許可なら undefined。 */
function denialReason(
  authorized: boolean,
  purposeAligned: boolean,
  categoryAllowed: boolean,
): string | undefined {
  if (!authorized || !categoryAllowed) {
    return ErrorCodes.RP_ACCESS_SCOPE_VIOLATION;
  }
  if (!purposeAligned) {
    return ErrorCodes.RP_ACCESS_PURPOSE_VIOLATION;
  }
  return undefined;
}

/**
 * 要求属性群を RP の認可スコープと突合する。
 *
 * @param requested RP が要求した属性群。
 * @param scope 証明書から抽出した認可スコープ。
 * @returns 属性ごとの権限判定。
 */
export function authorizeClaims(
  requested: readonly RequestedClaim[],
  scope: RpAuthorizedScope,
): ClaimAuthorization[] {
  return requested.map((claim) => authorizeClaim(claim, scope));
}

/** すべての要求属性が許可（属性・目的・カテゴリすべて OK）されているか。 */
export function allClaimsAuthorized(results: readonly ClaimAuthorization[]): boolean {
  return results.every((r) => r.authorized && r.purposeAligned && r.categoryAllowed);
}
