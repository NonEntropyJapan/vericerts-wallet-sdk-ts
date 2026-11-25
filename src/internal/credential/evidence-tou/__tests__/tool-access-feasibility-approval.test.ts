/**
 * Tool Access / Human Approval を既存の `termsOfUse`（ODRL 風）で表現できるかを、複合条件と承認条件について検証する。
 *
 * 単一 tool と語彙の評価は `tool-access-feasibility.test.ts` を参照。1 ファイルあたりの行数上限のため分割している。
 * 本テストも新機能の回帰テストではなく、**現行評価器の表現限界を固定する特性テスト**である。
 *
 * 検証内容:
 * - tool 名と承認状態の複合条件は「条件付きで可」。`UsageContext` に承認状態の専用枠が無いため、
 *   `spatial`（本来は ISO 3166-1 alpha-2 地域）等の既存 `leftOperand` を本来の意味から流用するか、
 *   `purpose` 単一文字列へ両者を連結符号化するしかない。同一 `leftOperand` に制約を並べる素直な
 *   書き方（`purpose` への 2 つの `eq`）では成立しない。
 * - Human Approval を `obligation` で「素直に」書くと実行を阻止できない。既定 `severity` は
 *   `warn` で `compliant` は `true` のまま。`severity: "deny"` を上書きしても、未知 `leftOperand`
 *   （`humanApproval` 等）は常に充足扱いで違反が出ない（無条件許可）。`purpose` 経路では deny 条件が
 *   `purpose` の値に縛られ、承認印を載せると tool 名を載せる枠を失うため両立しない。
 *   ただし `spatial` 等の評価可能な既存 `leftOperand` を流用すれば、`purpose` を tool 名の
 *   ままにしたうえで「承認があれば許可 / 無ければ deny」の承認ゲート自体は成立する（条件付きで可）。
 *   この使い方を採用すると、VC の利用条件とツールの実行可否を区別できなくなる。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../vc/vc.js';
import { checkTermsOfUse, type UsageContext } from '../terms-of-use.js';
import type { TermsOfUseEntry } from '../types.js';

/** termsOfUse を指定した最小 VC を作る（`tool-access-feasibility.test.ts` と同一の helper）。 */
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

describe('tool 名と承認状態の複合条件は既存 leftOperand の流用でしか表現できない', () => {
  it('purpose に対する 2 つの eq 制約は AND で同時に成立しない', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:tool-and-approval',
      permission: [
        {
          uid: 'urn:rule:allow-delete-if-approved',
          action: 'use',
          constraint: [
            { leftOperand: 'purpose', operator: 'eq', rightOperand: 'mcp:tool:delete_file' },
            { leftOperand: 'purpose', operator: 'eq', rightOperand: 'human-approved' },
          ],
        },
      ],
    };
    // tool 名を入れれば承認条件が落ち、承認印を入れれば tool 条件が落ちる。どちらも deny。
    const asTool = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    const asApproval = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('human-approved'));
    expect(asTool.compliant).toBe(false);
    expect(asApproval.compliant).toBe(false);
  });

  it('spatial へ載せ替えれば複合条件は成立する（既存 leftOperand の意味を流用する必要がある）', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:tool-and-approval-spatial',
      permission: [
        {
          uid: 'urn:rule:allow-delete-if-approved-spatial',
          action: 'use',
          constraint: [
            { leftOperand: 'purpose', operator: 'eq', rightOperand: 'mcp:tool:delete_file' },
            // `spatial` は odrl.ts で ISO 3166-1 alpha-2 の地域と定義された枠であり、
            // 承認状態を載せるのは本来の意味の流用。専用の枠が無いことの裏返しである。
            { leftOperand: 'spatial', operator: 'eq', rightOperand: 'human-approved' },
          ],
        },
      ],
    };
    const approved = await checkTermsOfUse(vcWithTou(tou), {
      verifierId: 'did:example:mcp-gateway',
      purpose: 'mcp:tool:delete_file',
      geolocation: 'human-approved',
      at: '2026-06-01T00:00:00Z',
    });
    expect(approved.compliant).toBe(true);
    expect(approved.violations).toHaveLength(0);
    // 承認印が無い（geolocation が本来の ISO 3166 値）文脈では permission allowlist により deny。
    const notApproved = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    expect(notApproved.compliant).toBe(false);
  });

  it('UsageContext には承認状態を運ぶ専用フィールドが無い（型は 4 フィールド固定）', async () => {
    // UsageContext は 4 フィールドのみ。フィールドが増減すれば
    // この型注釈がコンパイルエラーになり、フィールドの追加や削除を検知できる。
    const _usageContextFields: Record<keyof UsageContext, true> = {
      verifierId: true,
      purpose: true,
      geolocation: true,
      at: true,
    };
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:deny-delete-only',
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
    // 型に無い承認フィールドを足しても評価器は参照しない = 承認状態を運ぶ経路が存在しない。
    const withApproval = {
      ...gatewayCtx('mcp:tool:delete_file'),
      humanApproval: 'obtained',
    } as UsageContext;
    const base = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    const injected = await checkTermsOfUse(vcWithTou(tou), withApproval);
    expect(base.compliant).toBe(false);
    expect(injected.compliant).toBe(base.compliant);
  });
});

describe('obligation では「承認があれば許可」を素直に表現できない（既定 warn 止まり / deny 上書きは未知 leftOperand で無条件許可・purpose では tool 名と排他）', () => {
  const approvalObligation: TermsOfUseEntry = {
    id: 'urn:tou:human-approval',
    obligation: [
      {
        uid: 'urn:rule:require-human-approval',
        action: 'use',
        constraint: [{ leftOperand: 'humanApproval', operator: 'eq', rightOperand: 'obtained' }],
      },
    ],
  };

  it('未承認でも未知 leftOperand が true 扱いのため違反にすらならない', async () => {
    const result = await checkTermsOfUse(
      vcWithTou(approvalObligation),
      gatewayCtx('mcp:tool:delete_file'),
    );
    expect(result.compliant).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('評価可能な leftOperand を使っても obligation 未充足は既定 warn で compliant のまま', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:human-approval-purpose',
      obligation: [
        {
          uid: 'urn:rule:require-approval-purpose',
          action: 'use',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'human-approved' }],
        },
      ],
    };
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    // 違反は記録されるが severity=warn のため compliant=true。Gateway は実行を止められない。
    expect(result.compliant).toBe(true);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.severity).toBe('warn');
    expect(result.warnings).toHaveLength(1);
  });

  it('未知 leftOperand では severity="deny" 上書きも充足扱いで違反が出ない（無条件許可）', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:human-approval-deny',
      obligation: [
        {
          uid: 'urn:rule:require-approval-deny',
          action: 'use',
          severity: 'deny',
          constraint: [{ leftOperand: 'humanApproval', operator: 'eq', rightOperand: 'obtained' }],
        },
      ],
    };
    // 未知 leftOperand が true → 「充足」と判定され、承認の有無に関わらず違反が出ない。
    const result = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    expect(result.compliant).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('評価可能な leftOperand + severity="deny" は purpose の値に縛られた条件付き deny になる', async () => {
    const tou: TermsOfUseEntry = {
      id: 'urn:tou:human-approval-deny-purpose',
      obligation: [
        {
          uid: 'urn:rule:require-approval-deny-purpose',
          action: 'use',
          severity: 'deny',
          constraint: [{ leftOperand: 'purpose', operator: 'eq', rightOperand: 'human-approved' }],
        },
      ],
    };
    // tool 名を purpose に載せると obligation 未充足で deny。無条件拒否ではなく purpose 依存。
    const asTool = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('mcp:tool:delete_file'));
    expect(asTool.compliant).toBe(false);
    expect(asTool.violations.some((v) => v.severity === 'deny')).toBe(true);
    // `purpose` 経路で deny を回避するには purpose を承認印にするしかなく、その時点で tool 名を
    // 載せる枠を失う（`purpose` 経路に限った排他であり、`spatial` 経路には当てはまらない）。
    const asApproval = await checkTermsOfUse(vcWithTou(tou), gatewayCtx('human-approved'));
    expect(asApproval.compliant).toBe(true);
    expect(asApproval.violations).toHaveLength(0);
  });
});

describe('spatial を承認状態に流用すると、その値で許可を判定できる', () => {
  /**
   * `obligation` + `severity: "deny"` + 評価可能な既存 `leftOperand` の組合せは、
   * 「承認があれば許可 / 無ければ拒否」の承認ゲートとして実際に機能する。`purpose` は tool 名の
   * ままでよく、`purpose` 経路のような tool 名との排他も起きない。ただし `spatial` は odrl.ts で
   * ISO 3166-1 alpha-2 の地域と定義された枠であり、承認状態を載せると本来の用途と異なる。
   * この表現では地域に承認状態を割り当て、VC の利用条件である `termsOfUse` に tool の実行可否まで載せることになる。
   */
  const approvalGate: TermsOfUseEntry = {
    id: 'urn:tou:human-approval-deny-spatial',
    obligation: [
      {
        uid: 'urn:rule:require-approval-deny-spatial',
        action: 'use',
        severity: 'deny',
        constraint: [{ leftOperand: 'spatial', operator: 'eq', rightOperand: 'human-approved' }],
      },
    ],
  };

  it('承認印の有無で許可 / deny が分岐し、purpose は tool 名のまま使える', async () => {
    // 承認あり: obligation が充足され違反ゼロ。purpose には tool 名が載ったまま。
    const approved = await checkTermsOfUse(vcWithTou(approvalGate), {
      verifierId: 'did:example:mcp-gateway',
      purpose: 'mcp:tool:delete_file',
      geolocation: 'human-approved',
      at: '2026-06-01T00:00:00Z',
    });
    expect(approved.compliant).toBe(true);
    expect(approved.violations).toHaveLength(0);

    // 承認なし: 同じ tool 名の purpose のまま obligation 未充足 → severity=deny で実行を阻止できる。
    const notApproved = await checkTermsOfUse(
      vcWithTou(approvalGate),
      gatewayCtx('mcp:tool:delete_file'),
    );
    expect(notApproved.compliant).toBe(false);
    expect(notApproved.violations).toHaveLength(1);
    expect(notApproved.violations[0]?.ruleId).toBe('urn:rule:require-approval-deny-spatial');
    expect(notApproved.violations[0]?.severity).toBe('deny');
  });
});
