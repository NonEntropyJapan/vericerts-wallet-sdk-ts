/**
 * fail-closed 評価の回帰テスト。
 *
 * fail-open は「1 件でも不成立と分かった時点で打ち切る」ため到達しない経路が、fail-closed では
 * 全 constraint / 全ルールを評価するために新たに到達する。そこで露出した 2 件の取りこぼしを固定する:
 *
 * - 構造不正な `dateTime` 制約（不正 ISO）で評価が例外停止していた。構造不正な
 *   constraint は「判定不能」として `deny` 違反にする。Gateway での fail-closed 評価もこの挙動に依存する。
 * - `unknownAction: 'fail-closed'` で action 判定不能の deny を立てた際に allowlist 不成立の
 *   違反が重ねて積まれていた。permission が判定不能で deny になった場合、allowlist
 *   不成立の違反は重ねて積まない。この扱いは constraint と action の両経路に共通する。
 * - 不正 ISO を評価不能へ倒す際に、VC 本文由来の `rightOperand` だけでなく呼び出し側入力の
 *   `UsageContext.at` まで握り潰すと、呼び出し側のバグで全 `dateTime` 制約が黙って不成立になり
 *   発火すべき `prohibition` が消える（逆向きの fail-open）。`at` の不正は 3002 で表面化させる。
 * - `constraint` が配列でない単一オブジェクト（ODRL / JSON-LD では一般的な形）を「制約なし」と
 *   扱うと、fail-closed 指定時でもルールが無条件に成立し permission が常時許可になる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { checkTermsOfUse, type UsageContext } from '../terms-of-use.js';
import type { TermsOfUseEntry, ToUCheckOptions } from '../types.js';

function vcWithTou(tou: TermsOfUseEntry): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:agent' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id: 'urn:uuid:tool-access-vc',
    termsOfUse: tou,
  };
}

function ctx(purpose: string): UsageContext {
  return {
    verifierId: 'did:example:mcp-gateway',
    purpose,
    geolocation: 'JP',
    at: '2026-06-01T00:00:00Z',
  };
}

const STRICT_ACTION: ToUCheckOptions = { unknownAction: 'fail-closed' };
const STRICT_CONSTRAINT: ToUCheckOptions = { unknownConstraint: 'fail-closed' };

describe('構造不正な dateTime 制約は例外ではなく判定不能（deny）', () => {
  // 1 件目の purpose 制約が不成立なので fail-open は 2 件目に到達しない。
  // fail-closed は全件評価するため不正 ISO のパースに到達する。
  const tou: TermsOfUseEntry = {
    id: 'urn:tou:bad-datetime',
    prohibition: [
      {
        uid: 'urn:rule:bad-datetime',
        action: 'use',
        constraint: [
          { leftOperand: 'purpose', operator: 'eq', rightOperand: 'mcp:tool:other' },
          { leftOperand: 'dateTime', operator: 'lteq', rightOperand: 'NOT-A-DATE' },
        ],
      },
    ],
  };

  it('既定（fail-open）は従来どおり compliant（短絡して不正 ISO に到達しない）', async () => {
    const result = await checkTermsOfUse(vcWithTou(tou), ctx('mcp:tool:search'));
    expect(result.compliant).toBe(true);
  });

  it('unknownConstraint=fail-closed でも例外を投げず deny 違反として返す', async () => {
    const result = await checkTermsOfUse(vcWithTou(tou), ctx('mcp:tool:search'), STRICT_CONSTRAINT);
    expect(result.compliant).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.ruleId).toBe('urn:rule:bad-datetime');
    expect(result.violations[0]?.severity).toBe('deny');
  });

  it('不正 ISO の dateTime を持つ permission も例外にならない', async () => {
    const permTou: TermsOfUseEntry = {
      id: 'urn:tou:bad-datetime-permission',
      permission: [
        {
          uid: 'urn:rule:allow-bad-datetime',
          action: 'use',
          constraint: [{ leftOperand: 'dateTime', operator: 'lt', rightOperand: '2026-13-45' }],
        },
      ],
    };
    const result = await checkTermsOfUse(
      vcWithTou(permTou),
      ctx('mcp:tool:search'),
      STRICT_CONSTRAINT,
    );
    expect(result.compliant).toBe(false);
    expect(result.violations.map((v) => v.ruleId)).toContain('urn:rule:allow-bad-datetime');
  });

  it('正しい ISO の dateTime 制約は fail-closed でも通常評価のまま', async () => {
    const okTou: TermsOfUseEntry = {
      id: 'urn:tou:good-datetime',
      permission: [
        {
          uid: 'urn:rule:allow-until',
          action: 'use',
          constraint: [
            { leftOperand: 'dateTime', operator: 'lt', rightOperand: '2026-12-31T00:00:00Z' },
          ],
        },
      ],
    };
    const result = await checkTermsOfUse(
      vcWithTou(okTou),
      ctx('mcp:tool:search'),
      STRICT_CONSTRAINT,
    );
    expect(result.compliant).toBe(true);
  });
});

describe('action 判定不能の deny に allowlist 違反を重ねない', () => {
  // permission[0] は対象外 action（判定不能 → deny）、permission[1] は評価できるが purpose 不一致。
  // → allowlist は不成立だが、判定不能が 1 件あるので allowlist 違反は積まない。
  const tou: TermsOfUseEntry = {
    id: 'tou',
    permission: [
      {
        uid: 'tou#permission[0]',
        action: 'invoke',
      },
      {
        uid: 'tou#permission[1]',
        action: 'use',
        constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'Y' }],
      },
    ],
  };

  it('違反は action 判定不能の 1 件だけで allowlist 不成立を重複させない', async () => {
    const result = await checkTermsOfUse(vcWithTou(tou), ctx('Z'), STRICT_ACTION);
    expect(result.compliant).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.ruleId).toBe('tou#permission[0]');
    expect(result.violations.map((v) => v.ruleId)).not.toContain('tou#permission');
  });

  it('判定不能が無ければ allowlist 不成立の違反は従来どおり立つ', async () => {
    const evaluableTou: TermsOfUseEntry = {
      id: 'tou',
      permission: [
        {
          uid: 'tou#permission[0]',
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'Y' }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(evaluableTou), ctx('Z'), STRICT_ACTION);
    expect(result.compliant).toBe(false);
    expect(result.violations.map((v) => v.ruleId)).toContain('tou#permission');
  });

  it('constraint 経路の de-dup は従来どおり働く（回帰していないこと）', async () => {
    const constraintTou: TermsOfUseEntry = {
      id: 'tou',
      permission: [
        {
          uid: 'tou#permission[0]',
          action: 'use',
          constraint: [{ leftOperand: 'unknownLeft', operator: 'eq', rightOperand: 'X' }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(constraintTou), ctx('Z'), STRICT_CONSTRAINT);
    expect(result.compliant).toBe(false);
    expect(result.violations.map((v) => v.ruleId)).not.toContain('tou#permission');
  });
});

describe('呼び出し側入力（UsageContext.at）の不正は握り潰さない', () => {
  const tou: TermsOfUseEntry = {
    id: 'urn:tou:datetime-prohibition',
    prohibition: [
      {
        uid: 'urn:rule:deny-after',
        action: 'use',
        constraint: [
          { leftOperand: 'dateTime', operator: 'gt', rightOperand: '2020-01-01T00:00:00Z' },
        ],
      },
    ],
  };

  it('正しい at では prohibition が発火する', async () => {
    const result = await checkTermsOfUse(vcWithTou(tou), ctx('mcp:tool:search'));
    expect(result.compliant).toBe(false);
    expect(result.violations).toHaveLength(1);
  });

  it('不正な at は 3002 を送出し、prohibition を黙って消さない', async () => {
    const badCtx: UsageContext = { ...ctx('mcp:tool:search'), at: 'yesterday' };
    let thrown: unknown;
    try {
      await checkTermsOfUse(vcWithTou(tou), badCtx);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VericertsError);
    expect((thrown as VericertsError).code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('VC 本文由来の rightOperand の不正は従来どおり例外にしない', async () => {
    const badRight: TermsOfUseEntry = {
      id: 'urn:tou:bad-right',
      prohibition: [
        {
          action: 'use',
          constraint: [{ leftOperand: 'dateTime', operator: 'gt', rightOperand: 'not-a-date' }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(badRight), ctx('mcp:tool:search'));
    expect(result.compliant).toBe(true);
  });
});

describe('constraint の単数指定（非配列）も評価する', () => {
  /** `constraint` を単一オブジェクトで書いた permission（ODRL / JSON-LD で一般的な形）。 */
  const singleObject = {
    id: 'tou',
    permission: [
      {
        uid: 'tou#permission[0]',
        action: 'use',
        constraint: { leftOperand: 'purpose', operator: 'eq', rightOperand: 'kyc' },
      },
    ],
  } as unknown as TermsOfUseEntry;

  it('条件に合致しなければ permission は成立しない（fail-closed）', async () => {
    const result = await checkTermsOfUse(
      vcWithTou(singleObject),
      ctx('marketing'),
      STRICT_CONSTRAINT,
    );
    expect(result.compliant).toBe(false);
  });

  it('条件に合致しなければ permission は成立しない（fail-open 既定）', async () => {
    const result = await checkTermsOfUse(vcWithTou(singleObject), ctx('marketing'));
    expect(result.compliant).toBe(false);
  });

  it('条件に合致すれば permission が成立する', async () => {
    const result = await checkTermsOfUse(vcWithTou(singleObject), ctx('kyc'));
    expect(result.compliant).toBe(true);
  });

  it('単数指定の prohibition も発火する', async () => {
    const prohibition = {
      id: 'tou',
      prohibition: [
        {
          uid: 'tou#prohibition[0]',
          action: 'use',
          constraint: { leftOperand: 'purpose', operator: 'eq', rightOperand: 'marketing' },
        },
      ],
    } as unknown as TermsOfUseEntry;
    const result = await checkTermsOfUse(vcWithTou(prohibition), ctx('marketing'));
    expect(result.compliant).toBe(false);
  });

  it('constraint: null / 未指定は「制約なし」として扱う（prohibition は発火する）', async () => {
    // 単数正規化で null を 1 要素の配列にすると構造不正扱いになり、制約を持たない
    // prohibition が発火しなくなる（従来挙動からの後退）。
    const nullConstraint = {
      id: 'tou',
      prohibition: [{ uid: 'tou#prohibition[0]', action: 'use', constraint: null }],
    } as unknown as TermsOfUseEntry;
    const result = await checkTermsOfUse(vcWithTou(nullConstraint), ctx('anything'));
    expect(result.compliant).toBe(false);
    expect(result.violations.map((v) => v.ruleId)).toContain('tou#prohibition[0]');
  });
});
