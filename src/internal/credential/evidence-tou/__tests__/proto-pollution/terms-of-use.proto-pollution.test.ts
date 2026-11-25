/**
 * termsOfUse / ODRL 評価の `Object.prototype` 汚染耐性テスト。
 *
 * termsOfUse も evidence と同じく VC 本文由来のデータであり、`vc.termsOfUse` / `rule.constraint` /
 * `rule.severity` / `vp.verifiableCredential` をプロトタイプ鎖で読むと、**そのフィールドを持たない**
 * VC / ルールが汚染値を自分のものとして拾う。いずれも判定を緩める向き（fail-open）に倒れる:
 *
 * - `constraint` の継承: 無条件 prohibition に条件が生え、成立しない条件で `deny` が消える。
 * - `severity` の継承: `deny` が `warn` へ降格し、`compliant` が true に化ける。
 * - `termsOfUse` / `verifiableCredential` の継承: 利用条件を持たない VC・VC を含まない VP に
 *   攻撃者が選んだポリシー・クレデンシャルが生える。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { VerifiableCredential } from '../../../vc/vc.js';
import { checkTermsOfUse, validateTermsOfUseOnPresentation } from '../../terms-of-use.js';

const V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/** 提示先のみを指定した最小の利用文脈（`purpose` は**持たせない**）。 */
const CTX = { verifierId: 'did:example:verifier' } as const;

/** 無条件に成立する（constraint を持たない）禁止ルール 1 件を持つ termsOfUse エントリ。 */
const UNCONDITIONAL_PROHIBITION = { type: 'OdrlPolicy', prohibition: [{ action: 'use' }] } as const;

/**
 * `termsOfUse` を指定した最小 VC を作る。
 *
 * 未指定時は `termsOfUse` キー自体を生やさない（own プロパティの有無が検証対象のため）。
 */
function vcWithTou(tou?: VerifiableCredential['termsOfUse']): VerifiableCredential {
  return {
    '@context': [V2_CONTEXT],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    ...(tou !== undefined ? { termsOfUse: tou } : {}),
  };
}

describe('termsOfUse 評価の Object.prototype 汚染耐性', () => {
  it('継承した termsOfUse は VC 自身の利用条件として採用しない', async () => {
    // termsOfUse を持たない VC。汚染値は無条件 prohibition なので、拾えば必ず deny になる。
    const vc = vcWithTou();
    const result = await withPollutedPrototypeAsync(
      { termsOfUse: [UNCONDITIONAL_PROHIBITION] },
      () => checkTermsOfUse(vc, CTX),
    );
    expect(result.compliant).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('継承した constraint で無条件 prohibition の deny を消させない', async () => {
    // 自身の constraint を持たない = 無条件で成立する prohibition。
    const vc = vcWithTou({ prohibition: [{ action: 'use' }] });
    // `purpose` を持たない CTX に対し `isNoneOf` は不成立（compareString は left 未指定で false）。
    // 継承してしまうと「条件を満たさない」= 禁止に非該当となり、deny が消える。
    const result = await withPollutedPrototypeAsync(
      { constraint: [{ leftOperand: 'purpose', operator: 'isNoneOf', rightOperand: [] }] },
      () => checkTermsOfUse(vc, CTX),
    );
    expect(result.compliant).toBe(false);
    expect(result.violations.some((v) => v.severity === 'deny')).toBe(true);
  });

  it('継承した severity で deny を warn へ降格させない', async () => {
    const vc = vcWithTou({ prohibition: [{ action: 'use' }] });
    const result = await withPollutedPrototypeAsync({ severity: 'warn' }, () =>
      checkTermsOfUse(vc, CTX),
    );
    expect(result.compliant).toBe(false);
    expect(result.violations[0]?.severity).toBe('deny');
  });

  it('継承した verifiableCredential は VP 収録 VC として採用しない', async () => {
    // verifiableCredential を持たない VP ＝ 収録 VC 0 件。
    const vp = { id: 'urn:vp:1', type: ['VerifiablePresentation'] };
    const polluted = [vcWithTou(UNCONDITIONAL_PROHIBITION)];
    const result = await withPollutedPrototypeAsync({ verifiableCredential: polluted }, () =>
      validateTermsOfUseOnPresentation(vp, CTX),
    );
    expect(result.compliant).toBe(true);
    expect(result.perCredential).toHaveLength(0);
  });

  it('自身の termsOfUse / constraint は従来どおり評価される（正常系）', async () => {
    const vc = vcWithTou({
      prohibition: [
        {
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'marketing' }],
        },
      ],
    });
    const result = await checkTermsOfUse(vc, {
      verifierId: 'did:example:verifier',
      purpose: 'marketing',
    });
    expect(result.compliant).toBe(false);
    expect(result.violations[0]?.severity).toBe('deny');
  });
});
