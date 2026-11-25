/**
 * format-negotiation `evaluateFormatCapability` のユニットテスト。
 */

import { describe, expect, test } from 'bun:test';
import type { FormatDescriptor } from '../capability.js';
import { evaluateFormatCapability } from '../capability.js';
import { isSelectiveDisclosureCapable, type NegotiableCredential } from '../types.js';

const alwaysA = () => 0;

function vc(
  id: string,
  format: string,
  alg = 'ES256',
  supportsSelectiveDisclosure?: boolean,
): NegotiableCredential {
  return {
    id,
    format,
    alg,
    ...(supportsSelectiveDisclosure !== undefined ? { supportsSelectiveDisclosure } : {}),
  };
}

describe('evaluateFormatCapability', () => {
  test('全 descriptor を満たせる → fullyCovered、selection 生成', () => {
    const descriptors: FormatDescriptor[] = [
      {
        id: 'pid',
        vpFormats: { 'vc+sd-jwt': { alg: ['ES256'] } },
        candidates: [vc('sd-1', 'vc+sd-jwt')],
      },
      {
        id: 'diploma',
        vpFormats: { jwt_vc_json: { alg: ['ES256'] } },
        candidates: [vc('jwt-1', 'jwt_vc_json')],
      },
    ];
    const result = evaluateFormatCapability(descriptors, { randomTiebreak: alwaysA });
    expect(result.fullyCovered).toBe(true);
    expect(result.unmatchedDescriptors).toEqual([]);
    expect(result.selections).toHaveLength(2);
    expect(result.selections.map((s) => s.chosen.id)).toEqual(['sd-1', 'jwt-1']);
    expect(result.selections.map((s) => s.descriptorId)).toEqual(['pid', 'diploma']);
  });

  test('満たせない descriptor があれば unmatchedDescriptors に積み、fullyCovered=false', () => {
    const descriptors: FormatDescriptor[] = [
      {
        id: 'pid',
        vpFormats: { 'vc+sd-jwt': { alg: ['ES256'] } },
        candidates: [vc('sd-1', 'vc+sd-jwt')],
      },
      {
        id: 'mdl',
        vpFormats: { mso_mdoc: { alg: ['ES256'] } },
        candidates: [vc('sd-2', 'vc+sd-jwt')],
      },
    ];
    const result = evaluateFormatCapability(descriptors, { randomTiebreak: alwaysA });
    expect(result.fullyCovered).toBe(false);
    expect(result.unmatchedDescriptors).toEqual(['mdl']);
    expect(result.selections).toHaveLength(1);
    expect(result.warnings.some((w) => w.includes('mdl'))).toBe(true);
  });

  test('複数フォーマット要求で一部のみ対応可能 → 部分被覆の警告（4023 相当）', () => {
    const descriptors: FormatDescriptor[] = [
      {
        id: 'multi',
        vpFormats: { 'vc+sd-jwt': { alg: ['ES256'] }, mso_mdoc: { alg: ['ES256'] } },
        candidates: [vc('sd-1', 'vc+sd-jwt')],
      },
    ];
    const result = evaluateFormatCapability(descriptors, { randomTiebreak: alwaysA });
    // sd-jwt は選べるので descriptor 自体は充足（selection あり）。ただし mso_mdoc 未対応の警告が付く。
    expect(result.fullyCovered).toBe(true);
    expect(result.selections).toHaveLength(1);
    expect(result.selections[0]?.chosen.format).toBe('vc+sd-jwt');
    expect(result.warnings.some((w) => w.includes('mso_mdoc'))).toBe(true);
  });

  test('警告にクレーム値・VC 本文を含めない（descriptor ID とフォーマット名のみ）', () => {
    const descriptors: FormatDescriptor[] = [
      {
        id: 'pid',
        vpFormats: { mso_mdoc: {} },
        candidates: [],
      },
    ];
    const result = evaluateFormatCapability(descriptors);
    expect(result.warnings.length).toBeGreaterThan(0);
    for (const w of result.warnings) {
      expect(w).not.toContain('credentialSubject');
    }
  });

  // PEx の `constraints.limit_disclosure` が `required` でも、VC が選択的開示に対応しなければ VP を送信しない。
  describe('limit_disclosure', () => {
    test('required かつ候補が SD 非対応のみ → VP 不送信（unmatchedDescriptors に積む）', () => {
      const descriptors: FormatDescriptor[] = [
        {
          id: 'pid',
          vpFormats: { jwt_vc_json: { alg: ['ES256'] } },
          candidates: [vc('jwt-1', 'jwt_vc_json')],
          limitDisclosure: 'required',
        },
      ];
      const result = evaluateFormatCapability(descriptors, { randomTiebreak: alwaysA });
      expect(result.fullyCovered).toBe(false);
      expect(result.unmatchedDescriptors).toEqual(['pid']);
      expect(result.selections).toEqual([]);
      expect(result.warnings.some((w) => w.includes('pid') && w.includes('limit_disclosure'))).toBe(
        true,
      );
    });

    test('required かつ候補に SD 対応フォーマットが含まれる → 通常どおり選択される', () => {
      const descriptors: FormatDescriptor[] = [
        {
          id: 'pid',
          vpFormats: { 'vc+sd-jwt': { alg: ['ES256'] } },
          candidates: [vc('sd-1', 'vc+sd-jwt')],
          limitDisclosure: 'required',
        },
      ];
      const result = evaluateFormatCapability(descriptors, { randomTiebreak: alwaysA });
      expect(result.fullyCovered).toBe(true);
      expect(result.unmatchedDescriptors).toEqual([]);
      expect(result.selections.map((s) => s.chosen.id)).toEqual(['sd-1']);
    });

    test('required かつ SD 対応フォーマットでも supportsSelectiveDisclosure=false 明示なら除外', () => {
      const descriptors: FormatDescriptor[] = [
        {
          id: 'pid',
          vpFormats: { 'vc+sd-jwt': { alg: ['ES256'] } },
          candidates: [vc('sd-1', 'vc+sd-jwt', 'ES256', false)],
          limitDisclosure: 'required',
        },
      ];
      const result = evaluateFormatCapability(descriptors, { randomTiebreak: alwaysA });
      expect(result.fullyCovered).toBe(false);
      expect(result.unmatchedDescriptors).toEqual(['pid']);
    });

    test('preferred は非対応候補を除外しない（選択には影響しない）', () => {
      const descriptors: FormatDescriptor[] = [
        {
          id: 'pid',
          vpFormats: { jwt_vc_json: { alg: ['ES256'] } },
          candidates: [vc('jwt-1', 'jwt_vc_json')],
          limitDisclosure: 'preferred',
        },
      ];
      const result = evaluateFormatCapability(descriptors, { randomTiebreak: alwaysA });
      expect(result.fullyCovered).toBe(true);
      expect(result.selections.map((s) => s.chosen.id)).toEqual(['jwt-1']);
    });

    test('required でも候補が元々空なら limit_disclosure 固有の文言は付けない', () => {
      const descriptors: FormatDescriptor[] = [
        {
          id: 'pid',
          vpFormats: { jwt_vc_json: { alg: ['ES256'] } },
          candidates: [],
          limitDisclosure: 'required',
        },
      ];
      const result = evaluateFormatCapability(descriptors, { randomTiebreak: alwaysA });
      expect(result.unmatchedDescriptors).toEqual(['pid']);
      expect(result.warnings.some((w) => w.includes('limit_disclosure'))).toBe(false);
    });
  });
});

describe('isSelectiveDisclosureCapable', () => {
  test('supportsSelectiveDisclosure 明示があればそれを優先する', () => {
    expect(isSelectiveDisclosureCapable(vc('a', 'jwt_vc_json', 'ES256', true))).toBe(true);
    expect(isSelectiveDisclosureCapable(vc('b', 'vc+sd-jwt', 'ES256', false))).toBe(false);
  });

  test('未指定時はフォーマット既定値（SELECTIVE_DISCLOSURE_FORMATS）から推定する', () => {
    expect(isSelectiveDisclosureCapable(vc('a', 'vc+sd-jwt'))).toBe(true);
    expect(isSelectiveDisclosureCapable(vc('b', 'dc+sd-jwt'))).toBe(true);
    expect(isSelectiveDisclosureCapable(vc('c', 'mso_mdoc'))).toBe(true);
    expect(isSelectiveDisclosureCapable(vc('d', 'bbs+'))).toBe(true);
    expect(isSelectiveDisclosureCapable(vc('e', 'jwt_vc_json'))).toBe(false);
    expect(isSelectiveDisclosureCapable(vc('f', 'ldp_vc'))).toBe(false);
  });
});
