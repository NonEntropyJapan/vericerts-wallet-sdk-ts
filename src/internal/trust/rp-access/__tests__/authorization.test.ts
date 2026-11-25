import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { allClaimsAuthorized, authorizeClaims, isCrossBorder } from '../authorization.js';
import type { RpAuthorizedScope } from '../cert.js';
import type { RequestedClaim } from '../types.js';

const scope: RpAuthorizedScope = {
  attributes: ['family_name', 'age_over_18'],
  purposes: ['identification', 'age_verification'],
  categories: ['identification', 'authorization'],
};

describe('authorizeClaims', () => {
  test('認可集合に含まれる属性・目的・カテゴリはすべて許可される', () => {
    const claims: RequestedClaim[] = [
      { claimPath: 'family_name', purpose: 'identification', category: 'identification' },
    ];
    const result = authorizeClaims(claims, scope);
    expect(result[0]?.authorized).toBe(true);
    expect(result[0]?.purposeAligned).toBe(true);
    expect(result[0]?.categoryAllowed).toBe(true);
    expect(result[0]?.reason).toBeUndefined();
    expect(allClaimsAuthorized(result)).toBe(true);
  });

  test('認可集合に無い属性はスコープ違反で拒否される', () => {
    const claims: RequestedClaim[] = [
      { claimPath: 'given_name', purpose: 'identification', category: 'identification' },
    ];
    const result = authorizeClaims(claims, scope);
    expect(result[0]?.authorized).toBe(false);
    expect(result[0]?.reason).toBe(ErrorCodes.RP_ACCESS_SCOPE_VIOLATION);
    expect(allClaimsAuthorized(result)).toBe(false);
  });

  test('目的が Authorized Purposes に無い場合は purpose 違反で拒否される', () => {
    const claims: RequestedClaim[] = [
      { claimPath: 'family_name', purpose: 'marketing', category: 'identification' },
    ];
    const result = authorizeClaims(claims, scope);
    expect(result[0]?.authorized).toBe(true);
    expect(result[0]?.purposeAligned).toBe(false);
    expect(result[0]?.reason).toBe(ErrorCodes.RP_ACCESS_PURPOSE_VIOLATION);
  });

  test('カテゴリが許可外の場合はスコープ違反で拒否される', () => {
    const claims: RequestedClaim[] = [
      { claimPath: 'family_name', purpose: 'identification', category: 'authentication' },
    ];
    const result = authorizeClaims(claims, scope);
    expect(result[0]?.categoryAllowed).toBe(false);
    expect(result[0]?.reason).toBe(ErrorCodes.RP_ACCESS_SCOPE_VIOLATION);
  });

  test('認可属性集合が空なら fail-closed（すべて未認可）', () => {
    const emptyScope: RpAuthorizedScope = { attributes: [], purposes: [], categories: [] };
    const claims: RequestedClaim[] = [
      { claimPath: 'family_name', purpose: 'identification', category: 'identification' },
    ];
    const result = authorizeClaims(claims, emptyScope);
    // 属性集合が空 → 未認可。purpose/category は空集合=無制約。
    expect(result[0]?.authorized).toBe(false);
    expect(result[0]?.purposeAligned).toBe(true);
    expect(result[0]?.categoryAllowed).toBe(true);
  });
});

describe('isCrossBorder', () => {
  test('EU / EEA 加盟国は Cross-border ではない', () => {
    expect(isCrossBorder('DE')).toBe(false);
    expect(isCrossBorder('no')).toBe(false); // 大文字小文字非依存
  });

  test('第三国 / 不明は Cross-border 警告対象', () => {
    expect(isCrossBorder('US')).toBe(true);
    expect(isCrossBorder('')).toBe(true);
  });
});
