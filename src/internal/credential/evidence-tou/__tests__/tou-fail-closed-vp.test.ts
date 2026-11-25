/**
 * `validateTermsOfUseOnPresentation` への fail-closed オプション伝播テスト
 *
 * VP 内の各 VC の評価に `ToUCheckOptions` がそのまま渡り、1 件でも deny があれば VP 全体が
 * 非 compliant になることを確認する。単体の fail-closed 挙動は `tou-fail-closed.test.ts` を参照。
 */

import { describe, expect, it } from 'bun:test';
import type { VerifiableCredential } from '../../vc/vc.js';
import { type UsageContext, validateTermsOfUseOnPresentation } from '../terms-of-use.js';
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

const STRICT_CONSTRAINT: ToUCheckOptions = { unknownConstraint: 'fail-closed' };

describe('validateTermsOfUseOnPresentation へのオプション伝播', () => {
  const tou: TermsOfUseEntry = {
    id: 'urn:tou:vp',
    permission: [
      {
        uid: 'urn:rule:allow-by-toolname',
        action: 'use',
        constraint: [{ leftOperand: 'toolName', operator: 'eq', rightOperand: 'search' }],
      },
    ],
  };

  it('既定は fail-open で VP 全体が compliant', async () => {
    const vp = { verifiableCredential: [vcWithTou(tou)] };
    const result = await validateTermsOfUseOnPresentation(vp, gatewayCtx('mcp:tool:delete_file'));
    expect(result.compliant).toBe(true);
  });

  it('fail-closed を渡すと VP 全体が非 compliant になる', async () => {
    const vp = { verifiableCredential: [vcWithTou(tou)] };
    const result = await validateTermsOfUseOnPresentation(
      vp,
      gatewayCtx('mcp:tool:delete_file'),
      STRICT_CONSTRAINT,
    );
    expect(result.compliant).toBe(false);
    expect(result.perCredential[0]?.tou.compliant).toBe(false);
  });
});
