/**
 * PID Rulebook スキーマ検証テスト。
 *
 * - PID 型定義のスキーマ検証テスト
 * - Rulebook 準拠のユニットテスト（必須属性欠落 / 型不正 / age_over_NN 等）
 */

import { describe, expect, test } from 'bun:test';
import { validatePIDClaims, validatePIDSchema } from '../schema.js';
import type { PIDClaims, PIDCredential } from '../types.js';
import { PID_MANDATORY_ATTRIBUTES, PID_VCT } from '../types.js';

/** Rulebook 準拠の最小 PID クレーム（必須 7 属性）。 */
function validClaims(overrides: Partial<Record<string, unknown>> = {}): PIDClaims {
  return {
    family_name: 'Doe',
    given_name: 'Jane',
    birth_date: '1990-01-15',
    issuance_date: '2026-01-01',
    expiry_date: '2031-01-01',
    issuing_authority: 'Ministry of Interior',
    issuing_country: 'DE',
    ...overrides,
  } as PIDClaims;
}

function validPid(overrides: Partial<Record<string, unknown>> = {}): PIDCredential {
  return { vct: PID_VCT, claims: validClaims(overrides) };
}

describe('validatePIDClaims — Rulebook 準拠', () => {
  test('必須 7 属性が揃った PID は valid', () => {
    const result = validatePIDClaims(validClaims());
    expect(result.valid).toBe(true);
    expect(result.errors).toBeUndefined();
  });

  test('必須属性欠落を検出する（10002 相当）', () => {
    const claims = validClaims();
    delete (claims as Record<string, unknown>).family_name;
    delete (claims as Record<string, unknown>).issuing_country;
    const result = validatePIDClaims(claims);
    expect(result.valid).toBe(false);
    const paths = (result.errors ?? []).map((e) => e.path);
    expect(paths).toContain('family_name');
    expect(paths).toContain('issuing_country');
    // 欠落メッセージに属性値（PII）を含めない。
    for (const err of result.errors ?? []) {
      expect(err.message).toContain('必須属性');
    }
  });

  test('全必須属性を列挙している（Rulebook の 7 属性）', () => {
    expect([...PID_MANDATORY_ATTRIBUTES]).toEqual([
      'family_name',
      'given_name',
      'birth_date',
      'issuance_date',
      'expiry_date',
      'issuing_authority',
      'issuing_country',
    ]);
  });
});

describe('validatePIDClaims — 型・形式検証（10001 相当）', () => {
  test('date 属性が ISO 8601 でないと invalid', () => {
    const result = validatePIDClaims(validClaims({ birth_date: '15-01-1990' }));
    expect(result.valid).toBe(false);
    expect((result.errors ?? []).some((e) => e.path === 'birth_date')).toBe(true);
  });

  test('存在しない暦日（2 月 30 日）を弾く', () => {
    const result = validatePIDClaims(validClaims({ birth_date: '1990-02-30' }));
    expect(result.valid).toBe(false);
    expect((result.errors ?? []).some((e) => e.path === 'birth_date')).toBe(true);
  });

  test('issuing_country が alpha-2 でないと invalid', () => {
    expect(validatePIDClaims(validClaims({ issuing_country: 'DEU' })).valid).toBe(false);
    expect(validatePIDClaims(validClaims({ issuing_country: 'de' })).valid).toBe(false);
  });

  test('nationality が alpha-2 でないと invalid', () => {
    const result = validatePIDClaims(validClaims({ nationality: 'Germany' }));
    expect(result.valid).toBe(false);
    expect((result.errors ?? []).some((e) => e.path === 'nationality')).toBe(true);
  });

  test('age_over_NN が boolean なら valid、非 boolean なら invalid', () => {
    expect(validatePIDClaims(validClaims({ age_over_18: true })).valid).toBe(true);
    const bad = validatePIDClaims(validClaims({ age_over_21: 'yes' }));
    expect(bad.valid).toBe(false);
    expect((bad.errors ?? []).some((e) => e.path === 'age_over_21')).toBe(true);
  });

  test('age_in_years は非負整数のみ許容', () => {
    expect(validatePIDClaims(validClaims({ age_in_years: 36 })).valid).toBe(true);
    expect(validatePIDClaims(validClaims({ age_in_years: -1 })).valid).toBe(false);
    expect(validatePIDClaims(validClaims({ age_in_years: 3.5 })).valid).toBe(false);
  });

  test('任意属性 nationality を含む完全な PID は valid', () => {
    const result = validatePIDClaims(
      validClaims({ nationality: 'FR', age_over_18: true, age_in_years: 40 }),
    );
    expect(result.valid).toBe(true);
  });

  test('複数の違反をすべて集約する（最初で打ち切らない）', () => {
    const claims = validClaims({ birth_date: 'bad', issuing_country: 'xx' });
    delete (claims as Record<string, unknown>).given_name;
    const result = validatePIDClaims(claims);
    expect(result.valid).toBe(false);
    const paths = (result.errors ?? []).map((e) => e.path);
    expect(paths).toContain('given_name');
    expect(paths).toContain('birth_date');
    expect(paths).toContain('issuing_country');
  });
});

describe('validatePIDSchema — PIDCredential 全体', () => {
  test('正しい vct + Rulebook 準拠クレームは valid', () => {
    expect(validatePIDSchema(validPid()).valid).toBe(true);
  });

  test('vct が urn:eudi:pid:1 でないと invalid', () => {
    const pid = { vct: 'urn:eudi:pid:2', claims: validClaims() } as unknown as PIDCredential;
    const result = validatePIDSchema(pid);
    expect(result.valid).toBe(false);
    expect((result.errors ?? []).some((e) => e.path === 'vct')).toBe(true);
  });

  test('vct 不正 + クレーム欠落を同時に報告する', () => {
    const claims = validClaims();
    delete (claims as Record<string, unknown>).expiry_date;
    const pid = { vct: 'wrong', claims } as unknown as PIDCredential;
    const result = validatePIDSchema(pid);
    expect(result.valid).toBe(false);
    const paths = (result.errors ?? []).map((e) => e.path);
    expect(paths).toContain('vct');
    expect(paths).toContain('expiry_date');
  });
});

describe('SchemaError.required — 必須 / 任意の判別', () => {
  test('必須属性の欠落は required: true', () => {
    const claims = validClaims();
    delete (claims as Record<string, unknown>).family_name;
    const error = (validatePIDClaims(claims).errors ?? []).find((e) => e.path === 'family_name');
    expect(error?.required).toBe(true);
  });

  test('必須属性の型違反は required: true', () => {
    const error = (validatePIDClaims(validClaims({ birth_date: '1990-13-45' })).errors ?? []).find(
      (e) => e.path === 'birth_date',
    );
    expect(error?.required).toBe(true);
  });

  test('任意属性の型違反は required: false（FO-4 の対象）', () => {
    const result = validatePIDClaims(validClaims({ age_over_18: 'yes', nationality: 'de' }));
    expect(result.valid).toBe(false);
    for (const path of ['age_over_18', 'nationality']) {
      expect((result.errors ?? []).find((e) => e.path === path)?.required).toBe(false);
    }
  });

  test('vct 不一致は required: true', () => {
    const pid = { vct: 'urn:eudi:pid:2', claims: validClaims() } as unknown as PIDCredential;
    const result = validatePIDSchema(pid);
    expect(result.valid).toBe(false);
    expect((result.errors ?? []).find((e) => e.path === 'vct')?.required).toBe(true);
  });
});
