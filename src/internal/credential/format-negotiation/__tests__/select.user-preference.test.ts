/**
 * format-negotiation `selectBestVC` のユーザー優先度（お気に入り・直近の利用日時）のテスト。
 *
 * `userPreferenceScore` による優先度と同点時の選択を検証する。
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

describe('selectBestVC — ユーザー優先度', () => {
  test('期限が同点ならお気に入り指定の VC が優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({ id: 'plain', format: 'vc+sd-jwt', expirationDate: '2030-01-01T00:00:00Z' }),
      vc({
        id: 'favorite',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        isFavorite: true,
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe(
      'favorite',
    );
  });

  test('期限が異なる場合は期限がユーザー優先度より優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({ id: 'long-expiry', format: 'vc+sd-jwt', expirationDate: '2035-01-01T00:00:00Z' }),
      vc({
        id: 'favorite',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        isFavorite: true,
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe(
      'long-expiry',
    );
  });

  test('お気に入りが同値なら直近の利用日時（lastUsedAt）が新しい方が優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({
        id: 'used-old',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        lastUsedAt: '2026-01-01T00:00:00Z',
      }),
      vc({
        id: 'used-recent',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        lastUsedAt: '2026-06-01T00:00:00Z',
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe(
      'used-recent',
    );
  });

  test('lastUsedAt がある候補は未利用の候補より優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({ id: 'never-used', format: 'vc+sd-jwt', expirationDate: '2030-01-01T00:00:00Z' }),
      vc({
        id: 'used',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        lastUsedAt: '2026-01-01T00:00:00Z',
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe('used');
  });

  test('ユーザー優先度が同点なら issuanceDate が新しい方が勝つ', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({
        id: 'old-issued',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        issuanceDate: '2025-01-01T00:00:00Z',
      }),
      vc({
        id: 'new-issued',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        issuanceDate: '2026-01-01T00:00:00Z',
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe(
      'new-issued',
    );
  });
});
