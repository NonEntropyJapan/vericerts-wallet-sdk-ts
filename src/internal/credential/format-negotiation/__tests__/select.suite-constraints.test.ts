/**
 * `selectBestVC` / `canFulfillFormats` の proof_type / cryptosuite / -zkp_suite 制約に関する
 * ユニットテスト。
 *
 * 元は `select.test.ts` の一部（`Linterly` の行数上限対応での分割。テストケースの変更はない）。
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import { canFulfillFormats, selectBestVC } from '../select.js';
import type { NegotiableCredential, VpFormatRequirement } from '../types.js';

function vc(
  overrides: Partial<NegotiableCredential> & { id: string; format: string },
): NegotiableCredential {
  return {
    alg: 'ES256',
    ...overrides,
  } as NegotiableCredential;
}

describe('selectBestVC / canFulfillFormats — proof_type / cryptosuite / -zkp_suite', () => {
  test('ldp_vc: 要求 proof_type と異なる弱い proof を持つ VC は候補から除外される（ダウングレード拒否）', () => {
    const request: VpFormatRequirement = {
      ldp_vc: { proof_type: ['DataIntegrityProof'] },
    };
    const candidates = [
      vc({ id: 'weak', format: 'ldp_vc', alg: undefined, proofType: 'Ed25519Signature2018' }),
    ];
    expect(() => selectBestVC(request, candidates)).toThrow(VericertsError);
  });

  test('ldp_vc: 要求 proof_type に一致する VC は選択される', () => {
    const request: VpFormatRequirement = {
      ldp_vc: { proof_type: ['DataIntegrityProof'] },
    };
    const candidates = [
      vc({ id: 'strong', format: 'ldp_vc', alg: undefined, proofType: 'DataIntegrityProof' }),
    ];
    expect(selectBestVC(request, candidates).chosen.id).toBe('strong');
  });

  test('ldp_vc (Data Integrity v2): 要求 cryptosuite と異なる VC は除外される（ダウングレード拒否）', () => {
    const request: VpFormatRequirement = {
      ldp_vc: { cryptosuite: ['ecdsa-rdfc-2019'] },
    };
    const candidates = [
      vc({ id: 'weak', format: 'ldp_vc', alg: undefined, cryptosuite: 'ecdsa-2019' }),
    ];
    expect(() => selectBestVC(request, candidates)).toThrow(VericertsError);
  });

  test('bbs+: 要求 -zkp_suite と異なる VC は除外される（ダウングレード拒否）', () => {
    const request: VpFormatRequirement = {
      'bbs+': { '-zkp_suite': ['bbs-2023'] },
    };
    const candidates = [vc({ id: 'weak', format: 'bbs+', alg: undefined, zkpSuite: 'bbs-2020' })];
    expect(() => selectBestVC(request, candidates)).toThrow(VericertsError);
  });

  test('bbs+: 要求 -zkp_suite に一致する VC は選択される', () => {
    const request: VpFormatRequirement = {
      'bbs+': { '-zkp_suite': ['bbs-2023'] },
    };
    const candidates = [vc({ id: 'strong', format: 'bbs+', alg: undefined, zkpSuite: 'bbs-2023' })];
    expect(selectBestVC(request, candidates).chosen.id).toBe('strong');
  });

  test('制約に proof_type / cryptosuite / -zkp_suite が無ければ VC の値に依らず適合する', () => {
    const request: VpFormatRequirement = { ldp_vc: {} };
    const candidates = [
      vc({ id: 'x', format: 'ldp_vc', alg: undefined, proofType: 'Ed25519Signature2018' }),
    ];
    expect(selectBestVC(request, candidates).chosen.id).toBe('x');
  });

  test('canFulfillFormats: proof_type 不一致は未被覆扱い（ダウングレード拒否）', () => {
    const required: VpFormatRequirement = { ldp_vc: { proof_type: ['DataIntegrityProof'] } };
    const holding = [
      vc({ id: 's', format: 'ldp_vc', alg: undefined, proofType: 'Ed25519Signature2018' }),
    ];
    const coverage = canFulfillFormats(required, holding);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.unmatchedFormats).toEqual(['ldp_vc']);
  });
});
