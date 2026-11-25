/**
 * `selectBestVC` の alternatives / descriptorId に関するユニットテスト。
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

describe('selectBestVC — alternatives', () => {
  test('alternatives は最大 2 件', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': { alg: ['ES256'] } };
    const candidates = [
      vc({ id: 'a', format: 'vc+sd-jwt', expirationDate: '2033-01-01T00:00:00Z' }),
      vc({ id: 'b', format: 'vc+sd-jwt', expirationDate: '2032-01-01T00:00:00Z' }),
      vc({ id: 'c', format: 'vc+sd-jwt', expirationDate: '2031-01-01T00:00:00Z' }),
      vc({ id: 'd', format: 'vc+sd-jwt', expirationDate: '2030-01-01T00:00:00Z' }),
    ];
    const result = selectBestVC(request, candidates, { randomTiebreak: alwaysA });
    expect(result.chosen.id).toBe('a');
    expect(result.alternatives).toHaveLength(2);
    expect(result.alternatives.map((x) => x.id)).toEqual(['b', 'c']);
  });

  test('descriptorId がオプションで結果に伝播する', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [vc({ id: 'x', format: 'vc+sd-jwt' })];
    expect(selectBestVC(request, candidates, { descriptorId: 'pid' }).descriptorId).toBe('pid');
  });
});
