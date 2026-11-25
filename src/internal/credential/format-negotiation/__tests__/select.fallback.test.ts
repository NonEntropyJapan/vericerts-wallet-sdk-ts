/**
 * `selectBestVC` のフォールバック（要求を満たせない場合）に関するユニットテスト。
 *
 * 元は `select.test.ts` の一部（`Linterly` の行数上限対応での分割。テストケースの変更はない）。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { selectBestVC } from '../select.js';
import type { NegotiableCredential, VpFormatRequirement } from '../types.js';

function vc(
  overrides: Partial<NegotiableCredential> & { id: string; format: string },
): NegotiableCredential {
  return {
    alg: 'ES256',
    ...overrides,
  } as NegotiableCredential;
}

describe('selectBestVC — フォールバック', () => {
  test('case 2: mso_mdoc 要求だが sd-jwt のみ保持 → VP_FORMATS_NOT_SUPPORTED', () => {
    const request: VpFormatRequirement = { mso_mdoc: { alg: ['ES256'] } };
    const candidates = [vc({ id: 'sdjwt-1', format: 'vc+sd-jwt' })];
    expect(() => selectBestVC(request, candidates)).toThrow(VericertsError);
    try {
      selectBestVC(request, candidates);
    } catch (e) {
      expect((e as VericertsError).code).toBe(ErrorCodes.VP_FORMATS_NOT_SUPPORTED);
    }
  });

  test('case 3: alg 不一致（要求 ES384 / VC ES256）→ 候補除外で 3050', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': { alg: ['ES384'] } };
    const candidates = [vc({ id: 'sdjwt-1', format: 'vc+sd-jwt', alg: 'ES256' })];
    try {
      selectBestVC(request, candidates);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.VP_FORMATS_NOT_SUPPORTED);
    }
  });

  test('case 5: bbs+ 要求だが sd-jwt のみ → 全不一致で 3050', () => {
    const request: VpFormatRequirement = { 'bbs+': {} };
    const candidates = [vc({ id: 'sdjwt-1', format: 'vc+sd-jwt' })];
    expect(() => selectBestVC(request, candidates)).toThrow(VericertsError);
  });

  test('制約に alg が無ければ VC の alg に依らず適合する', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [vc({ id: 'sdjwt-1', format: 'vc+sd-jwt', alg: 'EdDSA' })];
    expect(selectBestVC(request, candidates).chosen.id).toBe('sdjwt-1');
  });
});
