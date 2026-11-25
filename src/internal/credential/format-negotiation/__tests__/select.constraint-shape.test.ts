/**
 * Verifier 由来 `vp_formats` の制約値が型不正でも、署名スイート制約をすり抜けず・例外にもならず
 * fail-closed になることの回帰テスト。
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import { canFulfillFormats, selectBestVC } from '../select.js';
import type { NegotiableCredential, VpFormatRequirement } from '../types.js';

const es256Vc: NegotiableCredential = { id: 'a', format: 'jwt_vc_json', alg: 'ES256' };
const ldpVc: NegotiableCredential = {
  id: 'b',
  format: 'ldp_vc',
  proofType: 'DataIntegrityProof',
  cryptosuite: 'ecdsa-rdfc-2019',
} as NegotiableCredential;

/** 型検査を迂回して生 JSON 相当の要求を作る。 */
const raw = (value: unknown): VpFormatRequirement => value as VpFormatRequirement;

describe('format-negotiation: 制約値の型検証', () => {
  test('alg が文字列だと部分一致（ES256 ⊂ ES256K）で制約をすり抜けず不適合', () => {
    const request = raw({ jwt_vc_json: { alg: 'ES256K' } });
    expect(canFulfillFormats(request, [es256Vc]).fullyCovered).toBe(false);
    expect(() => selectBestVC(request, [es256Vc])).toThrow(VericertsError);
  });

  test.each([
    ['数値', 5],
    ['オブジェクト', {}],
    ['null', null],
    ['真偽値', true],
    ['文字列以外を含む配列', ['ES256', 5]],
  ])('alg が %s でも throw せず不適合', (_label, alg) => {
    const request = raw({ jwt_vc_json: { alg } });
    expect(canFulfillFormats(request, [es256Vc]).fullyCovered).toBe(false);
    expect(() => selectBestVC(request, [es256Vc])).toThrow(VericertsError);
  });

  test.each([
    ['null', null],
    ['真偽値 true', true],
    ['文字列', 'ES256'],
    ['配列', ['ES256']],
    ['数値', 1],
  ])('フォーマット制約が %s でも throw せず fullyCovered: false', (_label, constraint) => {
    const request = raw({ jwt_vc_json: constraint });
    const coverage = canFulfillFormats(request, [es256Vc]);
    expect(coverage.fullyCovered).toBe(false);
    expect(coverage.unmatchedFormats).toEqual(['jwt_vc_json']);
    expect(() => selectBestVC(request, [es256Vc])).toThrow(VericertsError);
  });

  test('proof_type / cryptosuite / -zkp_suite の型不正も不適合', () => {
    for (const bad of [
      { proof_type: 'DataIntegrityProof' },
      { cryptosuite: 7 },
      { '-zkp_suite': null },
    ]) {
      expect(canFulfillFormats(raw({ ldp_vc: bad }), [ldpVc]).fullyCovered).toBe(false);
    }
  });

  test('対照: 正しい配列制約・空配列・空オブジェクトは従来どおり', () => {
    expect(
      canFulfillFormats(raw({ jwt_vc_json: { alg: ['ES256'] } }), [es256Vc]).fullyCovered,
    ).toBe(true);
    expect(canFulfillFormats(raw({ jwt_vc_json: { alg: [] } }), [es256Vc]).fullyCovered).toBe(true);
    expect(canFulfillFormats(raw({ jwt_vc_json: {} }), [es256Vc]).fullyCovered).toBe(true);
    expect(
      canFulfillFormats(raw({ jwt_vc_json: { alg: ['ES256K'] } }), [es256Vc]).fullyCovered,
    ).toBe(false);
  });
});
