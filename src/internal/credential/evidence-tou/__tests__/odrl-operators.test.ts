/**
 * ODRL `operator` 語彙の特性テスト。
 *
 * 型（`OdrlOperator`）・JSDoc・実装（`odrl.ts` の `compareString` / `compareDateTime`）が
 * 同じ語彙を指していることを実挙動で固定する。
 *
 * - 文字列制約（purpose / spatial）: `eq` / `neq` / `isAnyOf` / `isPartOf` / `isNoneOf`
 * - 時刻制約（dateTime）: `lt` / `lteq` / `gt` / `gteq` / `eq` / `neq`
 * - 対応外の組み合わせ・未知演算子は制約不成立（例外にはしない）
 *
 * 判定は permission（allowlist）経由で行う。制約成立 = compliant、不成立 = deny 違反。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../vc/vc.js';
import { checkTermsOfUse, type UsageContext } from '../terms-of-use.js';
import type { OdrlConstraint, OdrlOperator } from '../types.js';

const CTX: UsageContext = {
  verifierId: 'did:example:verifier',
  purpose: 'age-verification',
  geolocation: 'JP',
  at: '2026-06-01T00:00:00Z',
};

/** 単一 permission 制約だけを持つ VC を作る。 */
function vcWithPermissionConstraint(constraint: OdrlConstraint): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' },
    issuanceDate: '2026-01-01T00:00:00Z',
    termsOfUse: { id: 'policy', permission: [{ action: 'use', constraint: [constraint] }] },
  };
}

/** 制約が成立（permission が付与された）かを返す。 */
async function isSatisfied(constraint: OdrlConstraint): Promise<boolean> {
  const result = await checkTermsOfUse(vcWithPermissionConstraint(constraint), CTX);
  return result.compliant;
}

describe('文字列制約（purpose / spatial）の operator 語彙', () => {
  const cases: ReadonlyArray<{
    operator: OdrlOperator;
    rightOperand: string | readonly string[];
    expected: boolean;
  }> = [
    { operator: 'eq', rightOperand: 'age-verification', expected: true },
    { operator: 'eq', rightOperand: 'marketing', expected: false },
    { operator: 'neq', rightOperand: 'marketing', expected: true },
    { operator: 'neq', rightOperand: 'age-verification', expected: false },
    { operator: 'isAnyOf', rightOperand: ['age-verification', 'kyc'], expected: true },
    { operator: 'isAnyOf', rightOperand: ['kyc'], expected: false },
    { operator: 'isPartOf', rightOperand: ['age-verification', 'kyc'], expected: true },
    { operator: 'isPartOf', rightOperand: ['kyc'], expected: false },
    // isNoneOf は実装済みだが 以前は型・JSDoc に無かった演算子。
    { operator: 'isNoneOf', rightOperand: ['marketing', 'kyc'], expected: true },
    { operator: 'isNoneOf', rightOperand: ['age-verification'], expected: false },
  ];

  for (const { operator, rightOperand, expected } of cases) {
    it(`purpose ${operator} ${JSON.stringify(rightOperand)} → ${String(expected)}`, async () => {
      expect(await isSatisfied({ leftOperand: 'purpose', operator, rightOperand })).toBe(expected);
    });
  }

  it('spatial でも同じ演算子語彙が使える（isNoneOf 含む）', async () => {
    expect(
      await isSatisfied({ leftOperand: 'spatial', operator: 'isNoneOf', rightOperand: ['US'] }),
    ).toBe(true);
    expect(
      await isSatisfied({ leftOperand: 'spatial', operator: 'isNoneOf', rightOperand: ['JP'] }),
    ).toBe(false);
  });
});

describe('時刻制約（dateTime）の operator 語彙', () => {
  const NOW = '2026-06-01T00:00:00Z';
  const LATER = '2026-12-31T00:00:00Z';
  const EARLIER = '2026-01-01T00:00:00Z';

  const cases: ReadonlyArray<{ operator: OdrlOperator; right: string; expected: boolean }> = [
    { operator: 'lt', right: LATER, expected: true },
    { operator: 'lt', right: EARLIER, expected: false },
    { operator: 'lteq', right: NOW, expected: true },
    { operator: 'lteq', right: EARLIER, expected: false },
    { operator: 'gt', right: EARLIER, expected: true },
    { operator: 'gt', right: LATER, expected: false },
    { operator: 'gteq', right: NOW, expected: true },
    { operator: 'gteq', right: LATER, expected: false },
    { operator: 'eq', right: NOW, expected: true },
    { operator: 'eq', right: LATER, expected: false },
    { operator: 'neq', right: LATER, expected: true },
    { operator: 'neq', right: NOW, expected: false },
  ];

  for (const { operator, right, expected } of cases) {
    it(`dateTime ${operator} ${right} → ${String(expected)}`, async () => {
      expect(await isSatisfied({ leftOperand: 'dateTime', operator, rightOperand: right })).toBe(
        expected,
      );
    });
  }
});

describe('対応外の operator は制約不成立（例外にはしない）', () => {
  it('未知の演算子（文字列制約）は不成立', async () => {
    expect(
      await isSatisfied({ leftOperand: 'purpose', operator: 'startsWith', rightOperand: 'age' }),
    ).toBe(false);
  });

  it('未知の演算子（時刻制約）は不成立', async () => {
    expect(
      await isSatisfied({
        leftOperand: 'dateTime',
        operator: 'startsWith',
        rightOperand: '2026-06-01T00:00:00Z',
      }),
    ).toBe(false);
  });

  it('時刻専用演算子を文字列制約に使うと不成立', async () => {
    expect(
      await isSatisfied({ leftOperand: 'purpose', operator: 'lteq', rightOperand: 'zzz' }),
    ).toBe(false);
  });

  it('文字列専用演算子を時刻制約に使うと不成立', async () => {
    expect(
      await isSatisfied({
        leftOperand: 'dateTime',
        operator: 'isAnyOf',
        rightOperand: ['2026-06-01T00:00:00Z'],
      }),
    ).toBe(false);
  });
});
