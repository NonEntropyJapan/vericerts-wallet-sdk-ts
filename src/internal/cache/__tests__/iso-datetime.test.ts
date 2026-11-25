/**
 * 期限・有効期間境界がオフセット無し / 非 ISO の日時を受理せず、実行環境の TZ に依存しないこと。
 *
 * `Date.parse` 単独は `2026-09-01T00:00:00` を実行環境の TZ のローカル時刻として解釈し、
 * `'Dec 1 2025'` や `'1'` も数値にする。同じ VC の合否が検証環境で反転するため、
 * version-time と同じ「オフセット必須の ISO 8601」を共有パーサ経由で全境界に適用する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { isoToNumericDate } from '../../credential/vc/numeric-date.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isTrustedIssuer } from '../../trusted-issuer/trusted-issuer-list-store.js';
import type { TrustedIssuerList } from '../../trusted-issuer/types.js';
import { testSigner } from '../../wallet-migration/__tests__/fixtures.js';
import { createLend } from '../../wallet-migration/lend.js';
import { parseIsoDateOrDateTimeMs, parseIsoDateTimeMs } from '../iso-datetime.js';

const ORIGINAL_TZ = process.env.TZ;
const TIME_ZONES = ['UTC', 'Asia/Tokyo', 'America/Los_Angeles'] as const;
const AMBIGUOUS = [
  '2026-09-01T00:00:00',
  '2026-09-01T00:00:00.123',
  'Dec 1 2025',
  '1',
  '2026-09-01',
];

afterEach(() => {
  if (ORIGINAL_TZ === undefined) {
    delete process.env.TZ;
  } else {
    process.env.TZ = ORIGINAL_TZ;
  }
});

/** TZ を切り替えて fn を評価し、各 TZ の結果を返す。 */
function acrossTimeZones<T>(fn: () => T): T[] {
  return TIME_ZONES.map((tz) => {
    process.env.TZ = tz;
    return fn();
  });
}

describe('parseIsoDateTimeMs', () => {
  it('オフセット付き ISO 8601 は TZ に依らず同じ値になる', () => {
    for (const iso of [
      '2026-09-01T00:00:00Z',
      '2026-09-01T09:00:00+09:00',
      '2026-09-01T00:00:00.5Z',
    ]) {
      const results = acrossTimeZones(() => parseIsoDateTimeMs(iso));
      expect(new Set(results).size).toBe(1);
      expect(Number.isFinite(results[0])).toBe(true);
    }
  });

  it('オフセット無し・日付のみ・非 ISO・非文字列は NaN', () => {
    for (const value of [...AMBIGUOUS, '', undefined, null, 1, {}, Object.create(null)]) {
      expect(parseIsoDateTimeMs(value)).toBeNaN();
    }
  });
});

describe('parseIsoDateOrDateTimeMs', () => {
  it('日付のみ（UTC 0 時）は TZ に依らず同じ値、オフセット無し日時は NaN', () => {
    const results = acrossTimeZones(() => parseIsoDateOrDateTimeMs('2027-01-01'));
    expect(results).toEqual([Date.UTC(2027, 0, 1), Date.UTC(2027, 0, 1), Date.UTC(2027, 0, 1)]);
    expect(parseIsoDateOrDateTimeMs('2027-01-01T00:00:00')).toBeNaN();
    expect(parseIsoDateOrDateTimeMs('Dec 1 2025')).toBeNaN();
  });
});

describe('期限境界はオフセット無し / 非 ISO を TZ に依らず拒否する', () => {
  it('isoToNumericDate は 3002（issueCredential 側の発行も同じ関数経由）', () => {
    for (const iso of AMBIGUOUS) {
      acrossTimeZones(() =>
        expect(() => isoToNumericDate(iso)).toThrow(
          new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
        ),
      );
    }
    expect(isoToNumericDate('2025-12-01T00:00:00Z')).toBe(Date.UTC(2025, 11, 1) / 1000);
  });

  it('isTrustedIssuer はオフセット無しの期間を信頼しない', () => {
    const list = (validUntil: string): TrustedIssuerList =>
      ({
        trustedIssuers: [{ id: 'did:web:issuer.example', name: 'issuer', validUntil }],
      }) as unknown as TrustedIssuerList;
    const at = new Date('2026-06-01T00:00:00Z');
    acrossTimeZones(() =>
      expect(isTrustedIssuer(list('2099-01-01T00:00:00'), 'did:web:issuer.example', { at })).toBe(
        false,
      ),
    );
    expect(isTrustedIssuer(list('2099-01-01T00:00:00Z'), 'did:web:issuer.example', { at })).toBe(
      true,
    );
  });

  it('createLend はオフセット無しの valid_until を 4034 で拒否する', () => {
    const lender = { did: 'did:peer:2.Lender', signer: testSigner('did:key:lender#0') };
    acrossTimeZones(() =>
      expect(() =>
        createLend(['vc-1'], '2099-01-01T00:00:00', 'did:peer:2.Tablet', lender),
      ).toThrow(new VericertsError(ErrorCodes.W2W_LEND_EXPIRED)),
    );
  });
});

describe('暦として不正な日付は繰り上げずに NaN', () => {
  const INVALID_CALENDAR = [
    '2026-02-30T00:00:00Z',
    '2026-02-29T00:00:00Z', // 2026 は非うるう年
    '2026-04-31T23:59:59Z',
    '2026-00-10T00:00:00Z',
    '2026-13-10T00:00:00Z',
    '2026-01-00T00:00:00Z',
    '2026-01-01T24:00:00Z',
    '2026-12-31T24:00:00Z',
    '2026-01-01T00:60:00Z',
    '2026-01-01T00:00:60Z',
    '2026-01-01T00:00:00+24:00',
    '2026-01-01T00:00:00+09:60',
    '1900-02-29T00:00:00Z', // 100 で割れるが 400 で割れない
  ];

  it('parseIsoDateTimeMs は不正な暦・時刻・オフセットを NaN にする', () => {
    for (const value of INVALID_CALENDAR) {
      expect(parseIsoDateTimeMs(value)).toBeNaN();
    }
  });

  it('うるう日（2028-02-29 / 2000-02-29）や 23:59:59 は受理する', () => {
    expect(parseIsoDateTimeMs('2028-02-29T00:00:00Z')).toBe(Date.UTC(2028, 1, 29));
    expect(parseIsoDateTimeMs('2000-02-29T00:00:00Z')).toBe(Date.UTC(2000, 1, 29));
    expect(parseIsoDateTimeMs('2026-12-31T23:59:59Z')).toBe(Date.UTC(2026, 11, 31, 23, 59, 59));
    expect(parseIsoDateTimeMs('2026-01-01T00:00:00+23:59')).toBe(
      Date.UTC(2026, 0, 1) - (23 * 60 + 59) * 60_000,
    );
  });

  it('parseIsoDateOrDateTimeMs の日付のみも暦検証する', () => {
    expect(parseIsoDateOrDateTimeMs('2026-02-30')).toBeNaN();
    expect(parseIsoDateOrDateTimeMs('2026-04-31')).toBeNaN();
    expect(parseIsoDateOrDateTimeMs('2026-13-01')).toBeNaN();
    expect(parseIsoDateOrDateTimeMs('2028-02-29')).toBe(Date.UTC(2028, 1, 29));
  });

  it('isoToNumericDate は不正な暦を 3002 で拒否する（exp / nbf が数日ずれない）', () => {
    expect(() => isoToNumericDate('2026-02-31T23:59:59Z')).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});
