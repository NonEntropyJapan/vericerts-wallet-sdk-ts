/**
 * `selectBestVC` の alg 優先度・プライバシー優先度に関するユニットテスト。
 *
 * 元は `select.test.ts` の一部（`Linterly` の行数上限対応での分割。テストケースの変更はない）。
 */

import { describe, expect, test } from 'bun:test';
import { selectBestVC } from '../select.js';
import type { NegotiableCredential, VpFormatRequirement } from '../types.js';

/** 決定的タイブレーク(常に a を優先)。 */
const alwaysA = () => 0;

function vc(
  overrides: Partial<NegotiableCredential> & { id: string; format: string },
): NegotiableCredential {
  return {
    alg: 'ES256',
    ...overrides,
  } as NegotiableCredential;
}

describe('selectBestVC — alg 優先度', () => {
  test('要求 alg リストの先頭に一致する VC が優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': { alg: ['ES256', 'ES384'] } };
    const candidates = [
      vc({ id: 'es384', format: 'vc+sd-jwt', alg: 'ES384' }),
      vc({ id: 'es256', format: 'vc+sd-jwt', alg: 'ES256' }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe('es256');
  });
});

describe('selectBestVC — プライバシー優先度', () => {
  test('同フォーマット要求内で SD 対応 > Full Disclosure', () => {
    // 両フォーマットを同順で要求。プライバシー tier で sd-jwt(80) > jwt(30)。
    const request: VpFormatRequirement = {
      'vc+sd-jwt': { alg: ['ES256'] },
      jwt_vc_json: { alg: ['ES256'] },
    };
    const candidates = [
      vc({ id: 'jwt-1', format: 'jwt_vc_json' }),
      vc({ id: 'sd-1', format: 'vc+sd-jwt' }),
    ];
    // format 優先度で既に sd-jwt が勝つ。format 同順の検証は下の supportsSelectiveDisclosure で行う。
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe('sd-1');
  });

  test('supportsSelectiveDisclosure=false で同フォーマット内のプライバシーが下がる', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': { alg: ['ES256'] } };
    const candidates = [
      vc({
        id: 'sd-off',
        format: 'vc+sd-jwt',
        supportsSelectiveDisclosure: false,
        issuanceDate: '2026-01-01T00:00:00Z',
      }),
      vc({
        id: 'sd-on',
        format: 'vc+sd-jwt',
        supportsSelectiveDisclosure: true,
        issuanceDate: '2026-01-01T00:00:00Z',
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: () => 0.99 }).chosen.id).toBe(
      'sd-on',
    );
  });
});
