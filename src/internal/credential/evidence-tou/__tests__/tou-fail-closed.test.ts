/**
 * `checkTermsOfUse` の fail-closed オプションのテスト。
 *
 * `tool-access-feasibility.test.ts` で扱う対象外 `action` と未知の `leftOperand` を、
 * strict モードでは拒否することを検証する。
 * ファイル行数上限（300 行）のため別ファイルに分離しているが、対象は同じ特性である。
 *
 * 検証内容:
 * - `unknownAction: 'fail-closed'`: `use` / `present` / `*` 以外の action を持つルールを deny に倒す。
 * - `unknownConstraint: 'fail-closed'`: 未知 `leftOperand` / 対応外 `operator` / 構造不正を deny に倒す。
 * - 既定（オプション省略）は従来どおり fail-open のままであること。
 * - `validateTermsOfUseOnPresentation` への伝播は `tou-fail-closed-vp.test.ts` を参照。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../vc/vc.js';
import { checkTermsOfUse, type UsageContext } from '../terms-of-use.js';
import type { TermsOfUseEntry, ToUCheckOptions } from '../types.js';

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

/** MCP Gateway が tool 実行可否を問う文脈。 */
function gatewayCtx(purpose: string): UsageContext {
  return {
    verifierId: 'did:example:mcp-gateway',
    purpose,
    geolocation: 'JP',
    at: '2026-06-01T00:00:00Z',
  };
}

const STRICT_ACTION: ToUCheckOptions = { unknownAction: 'fail-closed' };
const STRICT_CONSTRAINT: ToUCheckOptions = { unknownConstraint: 'fail-closed' };

describe('strict モードで 対象外 action を fail-closed で deny に倒す', () => {
  const prohibitionTou: TermsOfUseEntry = {
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

  it('action="invoke" の prohibition は既定（fail-open）では無視される', async () => {
    const result = await checkTermsOfUse(
      vcWithTou(prohibitionTou),
      gatewayCtx('mcp:tool:delete_file'),
    );
    expect(result.compliant).toBe(true);
  });

  it('unknownAction=fail-closed では deny 違反になる', async () => {
    const result = await checkTermsOfUse(
      vcWithTou(prohibitionTou),
      gatewayCtx('mcp:tool:delete_file'),
      STRICT_ACTION,
    );
    expect(result.compliant).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.ruleId).toBe('urn:rule:deny-invoke-delete');
    expect(result.violations[0]?.severity).toBe('deny');
  });

  it('action="invoke" の permission も fail-closed では deny 違反になる', async () => {
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
    const result = await checkTermsOfUse(
      vcWithTou(tou),
      gatewayCtx('mcp:tool:search'),
      STRICT_ACTION,
    );
    expect(result.compliant).toBe(false);
    expect(result.violations.map((v) => v.ruleId)).toContain('urn:rule:allow-invoke-search');
  });

  it('評価対象の action（use / present / *）は fail-closed でも通常評価のまま', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:use-permission',
      permission: [
        {
          uid: 'urn:rule:allow-use',
          action: ['use', 'present'],
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'mcp:tool:search' }],
        },
      ],
    };
    const granted = await checkTermsOfUse(
      vcWithTou(tou),
      gatewayCtx('mcp:tool:search'),
      STRICT_ACTION,
    );
    expect(granted.compliant).toBe(true);
  });
});

describe('strict モードで 未知 leftOperand を fail-closed で deny に倒す', () => {
  const permissionTou: TermsOfUseEntry = {
    id: 'urn:tou:unknown-left-permission',
    permission: [
      {
        uid: 'urn:rule:allow-by-toolname',
        action: 'use',
        constraint: [{ leftOperand: 'toolName', operator: 'eq', rightOperand: 'search' }],
      },
    ],
  };

  it('未知 leftOperand の permission は既定（fail-open）では常時許可', async () => {
    const result = await checkTermsOfUse(
      vcWithTou(permissionTou),
      gatewayCtx('mcp:tool:delete_file'),
    );
    expect(result.compliant).toBe(true);
  });

  it('unknownConstraint=fail-closed では評価不能として deny になる', async () => {
    const result = await checkTermsOfUse(
      vcWithTou(permissionTou),
      gatewayCtx('mcp:tool:delete_file'),
      STRICT_CONSTRAINT,
    );
    expect(result.compliant).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.ruleId).toBe('urn:rule:allow-by-toolname');
    expect(result.violations[0]?.message).toContain('not evaluable');
  });

  it('fail-closed の permission 評価不能では allowlist 違反を重複して積まない', async () => {
    const result = await checkTermsOfUse(
      vcWithTou(permissionTou),
      gatewayCtx('mcp:tool:delete_file'),
      STRICT_CONSTRAINT,
    );
    expect(result.violations.map((v) => v.ruleId)).not.toContain(
      'urn:tou:unknown-left-permission#permission',
    );
  });

  it('未知 leftOperand の prohibition も fail-closed では deny（理由が評価不能に変わる）', async () => {
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
    const result = await checkTermsOfUse(
      vcWithTou(tou),
      gatewayCtx('mcp:tool:search'),
      STRICT_CONSTRAINT,
    );
    expect(result.compliant).toBe(false);
    expect(result.violations[0]?.message).toContain('not evaluable');
  });

  it('未知 leftOperand の obligation は fail-closed で warn ではなく deny になる', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:human-approval',
      obligation: [
        {
          uid: 'urn:rule:require-approval',
          action: 'use',
          constraint: [{ leftOperand: 'humanApproval', operator: 'eq', rightOperand: 'granted' }],
        },
      ],
    };
    const lenient = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    expect(lenient.compliant).toBe(true);

    const strict = await checkTermsOfUse(
      vcWithTou(tou),
      gatewayCtx('mcp:tool:delete_file'),
      STRICT_CONSTRAINT,
    );
    expect(strict.compliant).toBe(false);
    expect(strict.violations[0]?.severity).toBe('deny');
  });

  it('対応外 operator も fail-closed では評価不能として deny', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:bad-operator',
      permission: [
        {
          uid: 'urn:rule:bad-operator',
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'startsWith', rightOperand: 'mcp:' }],
        },
      ],
    };
    const strict = await checkTermsOfUse(
      vcWithTou(tou),
      gatewayCtx('mcp:tool:search'),
      STRICT_CONSTRAINT,
    );
    expect(strict.compliant).toBe(false);
    expect(strict.violations[0]?.message).toContain('not evaluable');
  });

  it('構造不正な constraint も fail-closed では評価不能として deny', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:malformed',
      permission: [
        {
          uid: 'urn:rule:malformed',
          action: 'use',
          constraint: [{ leftOperand: 'purpose' } as never],
        },
      ],
    };
    const strict = await checkTermsOfUse(
      vcWithTou(tou),
      gatewayCtx('mcp:tool:search'),
      STRICT_CONSTRAINT,
    );
    expect(strict.compliant).toBe(false);
    expect(strict.violations[0]?.message).toContain('not evaluable');
  });

  it('解釈できる制約だけのルールは fail-closed でも判定が変わらない', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:known-only',
      permission: [
        {
          uid: 'urn:rule:allow-search',
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'mcp:tool:search' }],
        },
      ],
    };
    const granted = await checkTermsOfUse(
      vcWithTou(tou),
      gatewayCtx('mcp:tool:search'),
      STRICT_CONSTRAINT,
    );
    expect(granted.compliant).toBe(true);

    const denied = await checkTermsOfUse(
      vcWithTou(tou),
      gatewayCtx('mcp:tool:delete_file'),
      STRICT_CONSTRAINT,
    );
    expect(denied.compliant).toBe(false);
    expect(denied.violations[0]?.ruleId).toBe('urn:tou:known-only#permission');
  });
});
