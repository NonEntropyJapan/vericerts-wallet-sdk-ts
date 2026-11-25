/**
 * `selectBestVC` の期限・タイブレークに関するユニットテスト。
 *
 * 元は `select.test.ts` の一部（`Linterly` の行数上限対応での分割。テストケースの変更はない）。
 */

import { describe, expect, spyOn, test } from 'bun:test';
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

describe('selectBestVC — 期限・タイブレーク', () => {
  test('長期有効な VC が優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': { alg: ['ES256'] } };
    const candidates = [
      vc({ id: 'short', format: 'vc+sd-jwt', expirationDate: '2026-08-01T00:00:00Z' }),
      vc({ id: 'long', format: 'vc+sd-jwt', expirationDate: '2030-08-01T00:00:00Z' }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: () => 0.99 }).chosen.id).toBe(
      'long',
    );
  });

  test('無期限（expirationDate 未設定）は有期限より優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({ id: 'expiring', format: 'vc+sd-jwt', expirationDate: '2030-08-01T00:00:00Z' }),
      vc({ id: 'forever', format: 'vc+sd-jwt' }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: () => 0.99 }).chosen.id).toBe(
      'forever',
    );
  });

  test('期限同点なら新しい issuanceDate が勝つ', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({
        id: 'old',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        issuanceDate: '2025-01-01T00:00:00Z',
      }),
      vc({
        id: 'new',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        issuanceDate: '2026-01-01T00:00:00Z',
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: () => 0.99 }).chosen.id).toBe('new');
  });

  test('case 6: 完全同点はタイブレーク乱数で選ばれる（相関回避）', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': { alg: ['ES256'] } };
    const base = {
      format: 'vc+sd-jwt',
      alg: 'ES256',
      expirationDate: '2030-01-01T00:00:00Z',
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    const candidates = [vc({ id: 'A', ...base }), vc({ id: 'B', ...base })];
    // Fisher–Yates で事前シャッフルし、完全同点をランダム順で確定する（相関回避）。
    // [A,B] に対し i=1: j=floor(r*2)。r=0.1→j=0→[B,A]（B が chosen）、r=0.9→j=1→[A,B]（A が chosen）。
    expect(selectBestVC(request, candidates, { randomTiebreak: () => 0.1 }).chosen.id).toBe('B');
    expect(selectBestVC(request, candidates, { randomTiebreak: () => 0.9 }).chosen.id).toBe('A');
    // どちらの候補も選ばれ得る（相関回避が機能している）ことを確認する。
    const picks = new Set<string>();
    for (let i = 0; i < 20; i++) {
      picks.add(selectBestVC(request, candidates).chosen.id);
    }
    expect(picks.size).toBe(2);
  });

  test('既定タイブレークは crypto.randomUUID() を乱数源に用いる', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': { alg: ['ES256'] } };
    const base = {
      format: 'vc+sd-jwt',
      alg: 'ES256',
      expirationDate: '2030-01-01T00:00:00Z',
      issuanceDate: '2026-01-01T00:00:00Z',
    };
    const candidates = [vc({ id: 'A', ...base }), vc({ id: 'B', ...base })];
    const randomUUIDSpy = spyOn(crypto, 'randomUUID');
    const getRandomValuesSpy = spyOn(crypto, 'getRandomValues');
    try {
      selectBestVC(request, candidates);
      expect(randomUUIDSpy).toHaveBeenCalled();
      expect(getRandomValuesSpy).not.toHaveBeenCalled();
    } finally {
      randomUUIDSpy.mockRestore();
      getRandomValuesSpy.mockRestore();
    }
  });
});
