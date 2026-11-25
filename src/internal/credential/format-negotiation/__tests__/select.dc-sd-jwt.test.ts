/**
 * format-negotiation が `dc+sd-jwt` を SD-JWT VC として扱えることのテスト。
 */

import { describe, expect, test } from 'bun:test';
import { SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY } from '../../sdjwt/typ.js';
import { canFulfillFormats, selectBestVC } from '../select.js';
import {
  type NegotiableCredential,
  PRIVACY_TIER,
  SELECTIVE_DISCLOSURE_FORMATS,
  type VpFormatRequirement,
} from '../types.js';

/** 決定的タイブレーク（常に先頭を優先）。 */
const alwaysA = () => 0;

function vc(id: string, format: string): NegotiableCredential {
  return { id, format, alg: 'ES256' };
}

describe('dc+sd-jwt のフォーマット属性', () => {
  test('選択的開示対応フォーマットに含まれる（新旧双方）', () => {
    expect(SELECTIVE_DISCLOSURE_FORMATS.has(SD_JWT_VC_TYP)).toBe(true);
    expect(SELECTIVE_DISCLOSURE_FORMATS.has(SD_JWT_VC_TYP_LEGACY)).toBe(true);
  });

  test('PRIVACY_TIER は新旧とも 80（Selective Disclosure 相当）', () => {
    expect(PRIVACY_TIER[SD_JWT_VC_TYP]).toBe(80);
    expect(PRIVACY_TIER[SD_JWT_VC_TYP_LEGACY]).toBe(80);
  });
});

describe('selectBestVC — dc+sd-jwt 要求', () => {
  test('vp_formats が dc+sd-jwt を最優先で要求すれば dc+sd-jwt 候補を選ぶ', () => {
    const request: VpFormatRequirement = {
      [SD_JWT_VC_TYP]: { alg: ['ES256'] },
      jwt_vc_json: { alg: ['ES256'] },
    };
    const result = selectBestVC(
      request,
      [vc('jwt-1', 'jwt_vc_json'), vc('sdjwt-dc-1', SD_JWT_VC_TYP)],
      { randomTiebreak: alwaysA },
    );
    expect(result.chosen.id).toBe('sdjwt-dc-1');
  });

  test('dc+sd-jwt のみ要求なら旧 vc+sd-jwt 候補は選択候補から除外される（完全一致が効く）', () => {
    const request: VpFormatRequirement = { [SD_JWT_VC_TYP]: { alg: ['ES256'] } };
    expect(() =>
      selectBestVC(request, [vc('sdjwt-legacy', SD_JWT_VC_TYP_LEGACY)], {
        randomTiebreak: alwaysA,
      }),
    ).toThrow();
  });
});

/**
 * 被覆判定（`canFulfillFormats`）での SD-JWT VC 新旧識別子の別名グループ化。
 *
 * Verifier が `vp_formats` に新旧を併記するのは「どちらの識別子で発行されたものでも受理する」
 * という意思表示なので、いずれか一方を保持していれば当該 SD-JWT VC 要求は被覆済みとする
 * （部分 VP 経路・4023 に落とさない）。ただし片方のみの要求は完全一致のままである。
 */
describe('canFulfillFormats — SD-JWT VC 新旧識別子の別名グループ', () => {
  const bothRequested: VpFormatRequirement = {
    [SD_JWT_VC_TYP]: { alg: ['ES256'] },
    [SD_JWT_VC_TYP_LEGACY]: { alg: ['ES256'] },
  };

  test('(a) 新旧併記 + dc+sd-jwt 保持 → 完全被覆（旧識別子を未被覆に残さない）', () => {
    const coverage = canFulfillFormats(bothRequested, [vc('sdjwt-dc-1', SD_JWT_VC_TYP)]);
    expect(coverage.fullyCovered).toBe(true);
    expect(coverage.matchedFormats).toEqual([SD_JWT_VC_TYP]);
    expect(coverage.unmatchedFormats).toEqual([]);
  });

  test('(b) 新旧併記 + vc+sd-jwt 保持 → 完全被覆（新識別子を未被覆に残さない）', () => {
    const coverage = canFulfillFormats(bothRequested, [vc('sdjwt-legacy', SD_JWT_VC_TYP_LEGACY)]);
    expect(coverage.fullyCovered).toBe(true);
    expect(coverage.matchedFormats).toEqual([SD_JWT_VC_TYP_LEGACY]);
    expect(coverage.unmatchedFormats).toEqual([]);
  });

  test('(c) dc+sd-jwt のみ要求 + vc+sd-jwt のみ保持 → 未被覆（クロスマッチしない）', () => {
    const request: VpFormatRequirement = { [SD_JWT_VC_TYP]: { alg: ['ES256'] } };
    const coverage = canFulfillFormats(request, [vc('sdjwt-legacy', SD_JWT_VC_TYP_LEGACY)]);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.matchedFormats).toEqual([]);
    expect(coverage.unmatchedFormats).toEqual([SD_JWT_VC_TYP]);
  });

  test('(c-2) vc+sd-jwt のみ要求 + dc+sd-jwt のみ保持 → 未被覆（逆向きもクロスマッチしない）', () => {
    const request: VpFormatRequirement = { [SD_JWT_VC_TYP_LEGACY]: { alg: ['ES256'] } };
    const coverage = canFulfillFormats(request, [vc('sdjwt-dc-1', SD_JWT_VC_TYP)]);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.unmatchedFormats).toEqual([SD_JWT_VC_TYP_LEGACY]);
  });

  test('(d) SD-JWT VC 以外のフォーマットの被覆判定は従来どおり独立要件のまま', () => {
    const request: VpFormatRequirement = {
      [SD_JWT_VC_TYP]: { alg: ['ES256'] },
      [SD_JWT_VC_TYP_LEGACY]: { alg: ['ES256'] },
      mso_mdoc: { alg: ['ES256'] },
      jwt_vc_json: { alg: ['ES256'] },
    };
    const coverage = canFulfillFormats(request, [
      vc('sdjwt-dc-1', SD_JWT_VC_TYP),
      vc('jwt-1', 'jwt_vc_json'),
    ]);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.matchedFormats).toEqual([SD_JWT_VC_TYP, 'jwt_vc_json']);
    // 別名グループ化で消えるのは SD-JWT VC の他方だけ。mso_mdoc は未被覆のまま残る。
    expect(coverage.unmatchedFormats).toEqual(['mso_mdoc']);
  });

  test('(d-2) 新旧併記でも alg 不一致で 1 件も一致しなければ双方が未被覆に残る', () => {
    const request: VpFormatRequirement = {
      [SD_JWT_VC_TYP]: { alg: ['ES384'] },
      [SD_JWT_VC_TYP_LEGACY]: { alg: ['ES384'] },
    };
    const coverage = canFulfillFormats(request, [vc('sdjwt-dc-1', SD_JWT_VC_TYP)]);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.unmatchedFormats).toEqual([SD_JWT_VC_TYP, SD_JWT_VC_TYP_LEGACY]);
  });
});
