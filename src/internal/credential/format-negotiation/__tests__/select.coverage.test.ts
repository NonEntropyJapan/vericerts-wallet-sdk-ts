/**
 * `canFulfillFormats`（被覆判定）に関するユニットテスト。
 *
 * 元は `select.test.ts` の一部（`Linterly` の行数上限対応での分割。テストケースの変更はない）。
 */

import { describe, expect, test } from 'bun:test';
import { canFulfillFormats } from '../select.js';
import type { NegotiableCredential, VpFormatRequirement } from '../types.js';

function vc(
  overrides: Partial<NegotiableCredential> & { id: string; format: string },
): NegotiableCredential {
  return {
    alg: 'ES256',
    ...overrides,
  } as NegotiableCredential;
}

describe('canFulfillFormats', () => {
  test('全要求フォーマットを保持 → fullyCovered', () => {
    const required: VpFormatRequirement = {
      'vc+sd-jwt': { alg: ['ES256'] },
      jwt_vc_json: { alg: ['ES256'] },
    };
    const holding = [vc({ id: 's', format: 'vc+sd-jwt' }), vc({ id: 'j', format: 'jwt_vc_json' })];
    const coverage = canFulfillFormats(required, holding);
    expect(coverage.fullyCovered).toBe(true);
    expect([...coverage.matchedFormats].sort()).toEqual(['jwt_vc_json', 'vc+sd-jwt']);
    expect(coverage.unmatchedFormats).toEqual([]);
  });

  test('一部のみ保持 → 部分被覆', () => {
    const required: VpFormatRequirement = {
      'vc+sd-jwt': { alg: ['ES256'] },
      mso_mdoc: { alg: ['ES256'] },
    };
    const holding = [vc({ id: 's', format: 'vc+sd-jwt' })];
    const coverage = canFulfillFormats(required, holding);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.matchedFormats).toEqual(['vc+sd-jwt']);
    expect(coverage.unmatchedFormats).toEqual(['mso_mdoc']);
  });

  test('alg 不一致は未被覆扱い（ダウングレード拒否）', () => {
    const required: VpFormatRequirement = { 'vc+sd-jwt': { alg: ['ES384'] } };
    const holding = [vc({ id: 's', format: 'vc+sd-jwt', alg: 'ES256' })];
    const coverage = canFulfillFormats(required, holding);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.unmatchedFormats).toEqual(['vc+sd-jwt']);
  });
});
