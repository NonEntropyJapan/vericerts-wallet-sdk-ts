/**
 * `permission` / `prohibition` / `obligation` の単一オブジェクト指定と形状不正の扱い。
 *
 * ODRL の JSON 表現は要素 1 件の規則を配列ではなく単一オブジェクトで書ける。規則側だけ配列限定
 * （`!Array.isArray → []`）にすると、`prohibition: { action: 'use' }` が黙って無視され、
 * `unknownConstraint: 'fail-closed'` を指定しても `compliant: true` になっていた。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../vc/vc.js';
import { checkTermsOfUse, type UsageContext } from '../terms-of-use.js';
import type { ToUCheckOptions } from '../types.js';

function vcWithTou(tou: Record<string, unknown>): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:agent' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id: 'urn:uuid:single-rule',
    termsOfUse: { id: 'tou', ...tou },
  } as unknown as VerifiableCredential;
}

const USAGE: UsageContext = {
  verifierId: 'did:example:verifier',
  purpose: 'kyc',
  geolocation: 'JP',
  at: '2026-06-01T00:00:00Z',
};

const FAIL_CLOSED: ToUCheckOptions = {
  unknownConstraint: 'fail-closed',
  unknownAction: 'fail-closed',
};

type Kind = 'prohibition' | 'permission' | 'obligation';

const RULES: Record<Kind, Record<string, unknown>> = {
  prohibition: { action: 'use' },
  permission: {
    action: 'use',
    constraint: { leftOperand: 'purpose', operator: 'eq', rightOperand: 'marketing' },
  },
  obligation: {
    action: 'use',
    constraint: { leftOperand: 'purpose', operator: 'eq', rightOperand: 'marketing' },
  },
};

describe('単一オブジェクトの規則は配列版と同じ violations になる', () => {
  for (const kind of ['prohibition', 'permission', 'obligation'] as const) {
    it(`${kind}: 単一オブジェクト === 1 要素配列`, async () => {
      const single = await checkTermsOfUse(vcWithTou({ [kind]: RULES[kind] }), USAGE);
      const array = await checkTermsOfUse(vcWithTou({ [kind]: [RULES[kind]] }), USAGE);
      expect(single.violations).toEqual(array.violations);
      expect(single.compliant).toBe(array.compliant);
    });
  }

  it('単一の prohibition は fail-open / fail-closed のどちらでも deny になる', async () => {
    for (const options of [undefined, FAIL_CLOSED]) {
      const result = await checkTermsOfUse(
        vcWithTou({ prohibition: { action: 'use' } }),
        USAGE,
        options,
      );
      expect(result.compliant).toBe(false);
      expect(result.violations).toHaveLength(1);
    }
  });

  it('単一の permission は合致しなければ allowlist 違反になる', async () => {
    const result = await checkTermsOfUse(vcWithTou({ permission: RULES.permission }), USAGE);
    expect(result.compliant).toBe(false);
  });

  it('単一の obligation は未充足なら warn になる', async () => {
    const result = await checkTermsOfUse(vcWithTou({ obligation: RULES.obligation }), USAGE);
    expect(result.compliant).toBe(true);
    expect(result.warnings).toHaveLength(1);
  });
});

describe('形状不正の規則は fail-closed で評価不能として報告する', () => {
  const MALFORMED: ReadonlyArray<readonly [string, unknown]> = [
    ['文字列', 'use'],
    ['数値', 5],
    ['真偽値', true],
    ['配列内の非オブジェクト要素', ['use', { action: 'present' }]],
  ];

  for (const kind of ['prohibition', 'permission', 'obligation'] as const) {
    it.each(
      MALFORMED,
    )(`${kind}: %s は fail-closed で deny、fail-open は従来どおり`, async (_name, value) => {
      const strict = await checkTermsOfUse(vcWithTou({ [kind]: value }), USAGE, FAIL_CLOSED);
      expect(strict.compliant).toBe(false);
      expect(strict.violations.some((v) => v.severity === 'deny')).toBe(true);

      const open = await checkTermsOfUse(vcWithTou({ [kind]: value }), USAGE);
      expect(open.violations.some((v) => v.message.includes('not evaluable'))).toBe(false);
    });
  }

  it('規則が無い（undefined / null）場合は違反を出さない', async () => {
    const result = await checkTermsOfUse(vcWithTou({ prohibition: null }), USAGE, FAIL_CLOSED);
    expect(result.compliant).toBe(true);
    expect(result.violations).toEqual([]);
  });
});
