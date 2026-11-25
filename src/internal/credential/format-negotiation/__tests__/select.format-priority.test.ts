/**
 * `selectBestVC` のフォーマット優先度に関するユニットテスト。
 *
 * 元は `select.test.ts` の一部（`Linterly` の行数上限対応での分割。テストケースの変更はない）。
 */

import { describe, expect, test } from 'bun:test';
import { selectBestVC } from '../select.js';
import type { NegotiableCredential, VpFormatRequirement } from '../types.js';

/** 決定的タイブレーク（常に a を優先）。 */
const alwaysA = () => 0;

function vc(
  overrides: Partial<NegotiableCredential> & { id: string; format: string },
): NegotiableCredential {
  return {
    alg: 'ES256',
    ...overrides,
  } as NegotiableCredential;
}

describe('selectBestVC — フォーマット優先度', () => {
  test('Verifier: [sd-jwt, jwt_vc_json]、両方保持 → sd-jwt が選ばれる', () => {
    const request: VpFormatRequirement = {
      'vc+sd-jwt': { alg: ['ES256'] },
      jwt_vc_json: { alg: ['ES256'] },
    };
    const candidates = [
      vc({ id: 'jwt-1', format: 'jwt_vc_json' }),
      vc({ id: 'sdjwt-1', format: 'vc+sd-jwt' }),
    ];
    const result = selectBestVC(request, candidates, { randomTiebreak: alwaysA });
    expect(result.chosen.id).toBe('sdjwt-1');
    expect(result.alternatives.map((a) => a.id)).toEqual(['jwt-1']);
  });

  test('要求並び順が優先度を決める（jwt_vc_json 先頭なら jwt が勝つ）', () => {
    const request: VpFormatRequirement = {
      jwt_vc_json: { alg: ['ES256'] },
      'vc+sd-jwt': { alg: ['ES256'] },
    };
    const candidates = [
      vc({ id: 'sdjwt-1', format: 'vc+sd-jwt' }),
      vc({ id: 'jwt-1', format: 'jwt_vc_json' }),
    ];
    const result = selectBestVC(request, candidates, { randomTiebreak: alwaysA });
    expect(result.chosen.id).toBe('jwt-1');
  });
});
