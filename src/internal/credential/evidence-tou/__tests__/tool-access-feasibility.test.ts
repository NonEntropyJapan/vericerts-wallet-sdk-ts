/**
 * Tool Access / Human Approval を既存の `termsOfUse`（ODRL 風）で表現できるかを、単一 tool と語彙について検証する。
 *
 * 現行評価器がどの条件を評価し、どの条件を無視するかを確認する。
 *
 * 検証内容:
 * - 単一 tool の allow / deny は `purpose` に tool 名を載せれば表現できる。
 * - `action` に tool 実行語彙（`invoke` 等）を置いたルールは評価器に無視され fail-open になる。
 * - 未知 `leftOperand`（`toolName` 等）は permission では常時許可、prohibition では常時拒否に
 *   縮退し、いずれも文脈非依存になる。
 * - `OdrlRule.target` は型に存在するが評価ロジックから参照されないため、ツールの絞り込みに
 *   使えない（`target` だけが異なる 2 つの ToU が同一の評価結果になる）。
 *
 * tool 名と承認状態の複合条件、および Human Approval の `obligation` 表現は
 * 1 ファイルあたりの行数上限のため `tool-access-feasibility-approval.test.ts` に分割している。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../vc/vc.js';
import { checkTermsOfUse, type UsageContext } from '../terms-of-use.js';
import type { TermsOfUseEntry } from '../types.js';

/** termsOfUse を指定した最小 VC を作る。 */
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

/** MCP Gateway が tool 実行可否を問う文脈。tool 名は `purpose` に載せるしかない。 */
function gatewayCtx(purpose: string): UsageContext {
  return {
    verifierId: 'did:example:mcp-gateway',
    purpose,
    geolocation: 'JP',
    at: '2026-06-01T00:00:00Z',
  };
}

describe('単一 tool の allow / deny は purpose で表現できる', () => {
  const tou: TermsOfUseEntry = {
    id: 'urn:tou:tool-access',
    type: 'odrl:Set',
    permission: [
      {
        uid: 'urn:rule:allow-search',
        action: 'use',
        constraint: [
          {
            leftOperand: 'purpose',
            operator: 'isAnyOf',
            rightOperand: ['mcp:tool:search', 'mcp:tool:read_file'],
          },
        ],
      },
    ],
    prohibition: [
      {
        uid: 'urn:rule:deny-delete',
        action: 'use',
        constraint: [
          { leftOperand: 'purpose', operator: 'eq', rightOperand: 'mcp:tool:delete_file' },
        ],
      },
    ],
  };

  it('allowlist に載る tool は compliant', async () => {
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:search'));
    expect(result.compliant).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('allowlist に無い tool は permission allowlist により deny', async () => {
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:write_file'));
    expect(result.compliant).toBe(false);
    expect(result.violations.some((v) => v.severity === 'deny')).toBe(true);
  });

  it('deniedActions 相当は prohibition で deny になる', async () => {
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    expect(result.compliant).toBe(false);
    expect(result.violations.map((v) => v.ruleId)).toContain('urn:rule:deny-delete');
  });
});

describe('tool 実行語彙を action に置くと評価器に無視される（fail-open）', () => {
  it('action="invoke" の prohibition は ruleActionScope に弾かれ発火しない', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:invoke-action',
      prohibition: [
        {
          uid: 'urn:rule:deny-invoke-delete',
          action: 'invoke',
          constraint: [
            { leftOperand: 'purpose', operator: 'eq', rightOperand: 'mcp:tool:delete_file' },
          ],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    // 禁止したはずの tool が compliant として通る = fail-open。
    expect(result.compliant).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('action="invoke" の permission は allowlist として機能しない', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:invoke-permission',
      permission: [
        {
          uid: 'urn:rule:allow-invoke-search',
          action: 'invoke',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'mcp:tool:search' }],
        },
      ],
    };
    // allowlist に無い tool でも、適用対象 permission が 0 件なので allowlist 判定が働かない。
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    expect(result.compliant).toBe(true);
    expect(result.violations).toHaveLength(0);
  });
});

describe('未知 leftOperand は文脈非依存に縮退する', () => {
  it('permission の未知 leftOperand は常に許可（fail-open）', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:unknown-left-permission',
      permission: [
        {
          uid: 'urn:rule:allow-by-toolname',
          action: 'use',
          constraint: [{ leftOperand: 'toolName', operator: 'eq', rightOperand: 'search' }],
        },
      ],
    };
    // toolName は評価器の対応 leftOperand ではないため常に true → どの文脈でも許可される。
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    expect(result.compliant).toBe(true);
  });

  it('prohibition の未知 leftOperand は常に拒否（過剰ブロック）', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:unknown-left-prohibition',
      prohibition: [
        {
          uid: 'urn:rule:deny-by-toolname',
          action: 'use',
          constraint: [{ leftOperand: 'toolName', operator: 'eq', rightOperand: 'delete_file' }],
        },
      ],
    };
    // delete_file を禁止したつもりでも、無関係な search でも同じく deny になる。
    const denied = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:search'));
    expect(denied.compliant).toBe(false);
    expect(denied.violations.map((v) => v.ruleId)).toContain('urn:rule:deny-by-toolname');
  });
});

describe('target はツールの絞り込みに使われない', () => {
  /** `target` の値だけが異なる ToU を作る（他の条件は完全に同一）。 */
  function touWithTarget(target: string): TermsOfUseEntry {
    return {
      id: 'urn:tou:target-scoping',
      permission: [
        {
          uid: 'urn:rule:allow-by-target',
          action: 'use',
          target,
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'invoice-triage' }],
        },
      ],
    };
  }

  it('target だけが異なる 2 つの ToU は同一の評価結果になる', async () => {
    const ctx = gatewayCtx('invoice-triage');
    const invoice = await checkTermsOfUse(
      vcWithTou(touWithTarget('urn:aegis:tool:invoice-api')),
      ctx,
    );
    const payment = await checkTermsOfUse(
      vcWithTou(touWithTarget('urn:aegis:tool:payment-api')),
      ctx,
    );

    // target が評価に影響するなら、この 2 件は別の結果になるはずである。
    expect(invoice.compliant).toBe(payment.compliant);
    expect(invoice.violations).toEqual(payment.violations);
    expect(invoice.compliant).toBe(true);
  });

  it('target 付き prohibition は constraint が無いと全ツールへ無差別に deny する', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:target-prohibition',
      prohibition: [
        {
          uid: 'urn:rule:deny-payment-api',
          action: 'use',
          target: 'urn:aegis:tool:payment-api',
          severity: 'deny',
        },
      ],
    };
    // payment-api だけを禁止したつもりでも、無関係な invoice-triage の文脈で発火する。
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('invoice-triage'));
    expect(result.compliant).toBe(false);
    expect(result.violations.map((v) => v.ruleId)).toContain('urn:rule:deny-payment-api');
  });

  it('target を allowlist に使っても permission の絞り込みにならない', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:target-allowlist',
      permission: [
        {
          uid: 'urn:rule:allow-invoice-api',
          action: 'use',
          target: 'urn:aegis:tool:invoice-api',
        },
      ],
    };
    // invoice-api だけを許可したつもりでも、constraint が無いため任意の文脈で充足する。
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    expect(result.compliant).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('restrictions は constraint 由来の 1 件のみで、target は UI へ伝わらない', async () => {
    const target = 'urn:aegis:tool:payment-api';
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:target-restrictions',
      prohibition: [
        {
          uid: 'urn:rule:deny-payment-api',
          action: 'use',
          target,
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'invoice-triage' }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('invoice-triage'));

    // extractRestrictions は constraint のみを読む。target を出力するようになれば件数が増えて落ちる。
    expect(result.restrictions).toEqual([
      { kind: 'purpose', description: 'prohibition: purpose eq invoice-triage' },
    ]);
    // ツール識別子は kind / description のどこにも現れず、UI は禁止対象ツールを知りようがない。
    for (const r of result.restrictions) {
      expect(r.kind).not.toContain(target);
      expect(r.description).not.toContain(target);
    }
  });
});
