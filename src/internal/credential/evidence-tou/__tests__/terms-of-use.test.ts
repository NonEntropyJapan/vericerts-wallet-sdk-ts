/**
 * VC `termsOfUse` の ODRL 風ポリシー評価と Verifier 側 VP 判定のユニット / 統合テスト
 *
 * 検証内容:
 * - checkTermsOfUse: prohibition 合致で deny、permission allowlist、obligation 未充足で warn。
 * - 制約評価: purpose（eq/isAnyOf）/ dateTime（lteq/gteq、有効期限）/ spatial（地域）。
 * - severity 上書き。restrictions 抽出。compliant / warnings 集計。
 * - validateTermsOfUseOnPresentation（統合）: VP 内複数 VC の評価と、1 件 deny で VP 全体 false。
 * - dateTime 制約の不正 ISO は例外ではなく制約不成立（fail-open 既定）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import {
  assertVpObject,
  checkTermsOfUse,
  type UsageContext,
  validateTermsOfUseOnPresentation,
} from '../terms-of-use.js';
import type { TermsOfUseEntry } from '../types.js';

/** termsOfUse を指定した最小 VC を作る。 */
function vcWithTou(tou: VerifiableCredential['termsOfUse'], id?: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' },
    issuanceDate: '2026-01-01T00:00:00Z',
    ...(id !== undefined ? { id } : {}),
    ...(tou !== undefined ? { termsOfUse: tou } : {}),
  };
}

const CTX: UsageContext = {
  verifierId: 'did:example:verifier',
  purpose: 'age-verification',
  geolocation: 'JP',
  at: '2026-06-01T00:00:00Z',
};

describe('checkTermsOfUse — prohibition', () => {
  it('purpose が禁止対象に合致すると deny 違反', async () => {
    const tou: TermsOfUseEntry = {
      id: 'policy-1',
      prohibition: [
        {
          uid: 'no-marketing',
          action: 'use',
          constraint: [
            { leftOperand: 'purpose', operator: 'eq', rightOperand: 'age-verification' },
          ],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), CTX);
    expect(result.compliant).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.severity).toBe('deny');
    expect(result.violations[0]?.ruleId).toBe('no-marketing');
  });

  it('禁止 constraint に合致しなければ違反なし', async () => {
    const tou: TermsOfUseEntry = {
      prohibition: [
        {
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'marketing' }],
        },
      ],
    };
    expect((await checkTermsOfUse(vcWithTou(tou), CTX)).compliant).toBe(true);
  });

  it('地域（spatial isAnyOf）で禁止判定する', async () => {
    const tou: TermsOfUseEntry = {
      prohibition: [
        {
          action: 'use',
          constraint: [{ leftOperand: 'spatial', operator: 'isAnyOf', rightOperand: ['US', 'JP'] }],
        },
      ],
    };
    expect((await checkTermsOfUse(vcWithTou(tou), CTX)).compliant).toBe(false);
  });
});

describe('checkTermsOfUse — permission (allowlist)', () => {
  it('permission のいずれにも合致しなければ deny', async () => {
    const tou: TermsOfUseEntry = {
      id: 'policy-2',
      permission: [
        {
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'kyc-onboarding' }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), CTX);
    expect(result.compliant).toBe(false);
    expect(result.violations[0]?.ruleId).toBe('policy-2#permission');
  });

  it('permission に合致すれば compliant', async () => {
    const tou: TermsOfUseEntry = {
      permission: [
        {
          action: 'use',
          constraint: [
            {
              leftOperand: 'purpose',
              operator: 'isAnyOf',
              rightOperand: ['age-verification', 'kyc'],
            },
          ],
        },
      ],
    };
    expect((await checkTermsOfUse(vcWithTou(tou), CTX)).compliant).toBe(true);
  });
});

describe('checkTermsOfUse — dateTime constraint', () => {
  it('lteq 有効期限内なら permission 合致', async () => {
    const tou: TermsOfUseEntry = {
      permission: [
        {
          action: 'use',
          constraint: [
            { leftOperand: 'dateTime', operator: 'lteq', rightOperand: '2026-12-31T00:00:00Z' },
          ],
        },
      ],
    };
    expect((await checkTermsOfUse(vcWithTou(tou), CTX)).compliant).toBe(true);
  });

  it('lteq 期限超過なら permission 不成立で deny', async () => {
    const tou: TermsOfUseEntry = {
      permission: [
        {
          action: 'use',
          constraint: [
            { leftOperand: 'dateTime', operator: 'lteq', rightOperand: '2026-01-01T00:00:00Z' },
          ],
        },
      ],
    };
    expect((await checkTermsOfUse(vcWithTou(tou), CTX)).compliant).toBe(false);
  });

  it('不正 ISO の dateTime 制約は例外ではなく制約不成立（fail-open 既定）', async () => {
    // 構造不正な constraint は「判定不能」であり、既定の fail-open では
    // 制約不成立（ルールが発火しない）に倒す。deny に倒したい場合は
    // `unknownConstraint: 'fail-closed'` を使う（tou-fail-closed-regressions.test.ts）。
    const tou: TermsOfUseEntry = {
      prohibition: [
        {
          action: 'use',
          constraint: [{ leftOperand: 'dateTime', operator: 'lteq', rightOperand: 'not-a-date' }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), CTX);
    expect(result.compliant).toBe(true);
  });
});

describe('checkTermsOfUse — obligation & restrictions', () => {
  it('obligation 未充足は warn（compliant は維持）', async () => {
    const tou: TermsOfUseEntry = {
      obligation: [
        {
          uid: 'log-usage',
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'audit' }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), CTX);
    expect(result.compliant).toBe(true);
    expect(result.warnings).toContain('obligation not fulfilled');
    expect(result.violations[0]?.severity).toBe('warn');
  });

  it('severity 上書きで prohibition を warn に降格できる', async () => {
    const tou: TermsOfUseEntry = {
      prohibition: [
        {
          uid: 'soft',
          action: 'use',
          severity: 'warn',
          constraint: [
            { leftOperand: 'purpose', operator: 'eq', rightOperand: 'age-verification' },
          ],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), CTX);
    expect(result.compliant).toBe(true);
    expect(result.violations[0]?.severity).toBe('warn');
  });

  it('制約を restrictions として抽出する', async () => {
    const tou: TermsOfUseEntry = {
      permission: [
        {
          action: 'use',
          constraint: [{ leftOperand: 'spatial', operator: 'isAnyOf', rightOperand: ['JP'] }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), CTX);
    expect(result.restrictions.some((r) => r.kind === 'spatial')).toBe(true);
  });

  it('termsOfUse 無しは compliant', async () => {
    expect((await checkTermsOfUse(vcWithTou(undefined), CTX)).compliant).toBe(true);
  });
});

describe('validateTermsOfUseOnPresentation (統合)', () => {
  it('VP 内全 VC が compliant なら VP も compliant', async () => {
    const vp = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      verifiableCredential: [
        vcWithTou(undefined, 'vc-1'),
        vcWithTou(
          {
            permission: [
              {
                action: 'use',
                constraint: [
                  { leftOperand: 'purpose', operator: 'eq', rightOperand: 'age-verification' },
                ],
              },
            ],
          },
          'vc-2',
        ),
      ],
    };
    const result = await validateTermsOfUseOnPresentation(vp, CTX);
    expect(result.compliant).toBe(true);
    expect(result.perCredential).toHaveLength(2);
  });

  it('1 件でも deny 違反があれば VP 全体を非遵守と判定する', async () => {
    const vp = {
      type: ['VerifiablePresentation'],
      verifiableCredential: [
        vcWithTou(undefined, 'vc-ok'),
        vcWithTou(
          {
            id: 'policy-x',
            prohibition: [
              {
                action: 'use',
                constraint: [
                  { leftOperand: 'purpose', operator: 'eq', rightOperand: 'age-verification' },
                ],
              },
            ],
          },
          'vc-bad',
        ),
      ],
    };
    const result = await validateTermsOfUseOnPresentation(vp, CTX);
    expect(result.compliant).toBe(false);
    const bad = result.perCredential.find((p) => p.vcId === 'vc-bad');
    expect(bad?.tou.compliant).toBe(false);
  });

  it('単一 VC（object）の verifiableCredential も受理する', async () => {
    const vp = {
      type: ['VerifiablePresentation'],
      verifiableCredential: vcWithTou(undefined, 'vc-solo'),
    };
    const result = await validateTermsOfUseOnPresentation(vp, CTX);
    expect(result.perCredential).toHaveLength(1);
    expect(result.perCredential[0]?.vcId).toBe('vc-solo');
  });

  it('文字列（JWT）形式の VP は VC_SCHEMA_INVALID（3002）で拒否する', async () => {
    let thrown: unknown;
    try {
      await validateTermsOfUseOnPresentation('eyJ...jwt-vp', CTX);
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });
});

describe('assertVpObject', () => {
  it('文字列 VP は VC_SCHEMA_INVALID（3002）で拒否する', async () => {
    let thrown: unknown;
    try {
      assertVpObject('eyJ...jwt');
    } catch (e) {
      thrown = e;
    }
    expect((thrown as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('object VP はそのまま返す', async () => {
    const vp = { type: ['VerifiablePresentation'] };
    expect(assertVpObject(vp)).toBe(vp);
  });
});
