/**
 * format-negotiation `selectBestVC` の鍵バインディング可用性（cnf 所有鍵が利用可能）のテスト
 *
 * 鍵バインディングより有効期限を優先し、ユーザー優先度より鍵バインディングを優先する。
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

describe('selectBestVC — 鍵バインディング可用性', () => {
  test('cnf 所有鍵を保持する VC が、保持していないと判明した VC より優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({
        id: 'no-key',
        format: 'vc+sd-jwt',
        cnf: { kid: 'holder-key-1' },
        hasBoundKey: false,
      }),
      vc({
        id: 'has-key',
        format: 'vc+sd-jwt',
        cnf: { kid: 'holder-key-2' },
        hasBoundKey: true,
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe(
      'has-key',
    );
  });

  test('判定不能（hasBoundKey 未設定）は中立で、保持していないと判明した VC より優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({ id: 'no-key', format: 'vc+sd-jwt', cnf: { kid: 'holder-key-1' }, hasBoundKey: false }),
      vc({ id: 'unknown', format: 'vc+sd-jwt' }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe(
      'unknown',
    );
  });

  test('期限が鍵バインディング可用性より優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({
        id: 'long-expiry-no-key',
        format: 'vc+sd-jwt',
        expirationDate: '2035-01-01T00:00:00Z',
        hasBoundKey: false,
      }),
      vc({
        id: 'short-expiry-has-key',
        format: 'vc+sd-jwt',
        expirationDate: '2030-01-01T00:00:00Z',
        hasBoundKey: true,
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe(
      'long-expiry-no-key',
    );
  });

  test('鍵バインディング可用性が異なる場合はユーザー優先度（手順 7）より優先される', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({
        id: 'favorite-no-key',
        format: 'vc+sd-jwt',
        isFavorite: true,
        hasBoundKey: false,
      }),
      vc({
        id: 'plain-has-key',
        format: 'vc+sd-jwt',
        hasBoundKey: true,
      }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe(
      'plain-has-key',
    );
  });

  test('全候補が既存フィールドのみ（hasBoundKey 未設定）の場合は既存の挙動を維持する', () => {
    const request: VpFormatRequirement = { 'vc+sd-jwt': {} };
    const candidates = [
      vc({ id: 'old', format: 'vc+sd-jwt', issuanceDate: '2025-01-01T00:00:00Z' }),
      vc({ id: 'new', format: 'vc+sd-jwt', issuanceDate: '2026-01-01T00:00:00Z' }),
    ];
    expect(selectBestVC(request, candidates, { randomTiebreak: alwaysA }).chosen.id).toBe('new');
  });
});
