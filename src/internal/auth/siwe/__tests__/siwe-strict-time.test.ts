/**
 * parseSiweMessage / validateSiweMessage の日時は、viem の `new Date(str)`（オフセット無しを実行 TZ の
 * ローカル時刻として解釈し、非 ISO も受理する）に依らず、オフセット必須の厳格 ISO 8601 で検証する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  generateSiweMessage,
  parseSiweMessage,
  type SiweParams,
  validateSiweMessage,
} from '../siwe.js';

const ORIGINAL_TZ = process.env.TZ;
const TIME_ZONES = ['UTC', 'Pacific/Kiritimati', 'America/Los_Angeles'] as const;

const baseParams: SiweParams = {
  domain: 'example.com',
  address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  uri: 'https://example.com/login',
  nonce: 'abcd1234',
  chainId: 1,
  issuedAt: new Date('2026-07-02T00:00:00.000Z'),
};

afterEach(() => {
  if (ORIGINAL_TZ === undefined) {
    delete process.env.TZ;
  } else {
    process.env.TZ = ORIGINAL_TZ;
  }
});

/** 生成済みメッセージの日時行を差し替える。 */
function withLine(label: string, value: string, extra = ''): string {
  return `${generateSiweMessage(baseParams)}\n${label}: ${value}${extra}`;
}

function expectInvalid(fn: () => unknown): void {
  try {
    fn();
    throw new Error('should have thrown');
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.SIWE_MESSAGE_INVALID);
  }
}

describe('parseSiweMessage の日時は TZ 非依存の厳格 ISO 8601', () => {
  it('オフセット無し・非 ISO・暦として不正な日時は TZ に依らず 8041', () => {
    for (const bad of ['2026-10-01T12:00:00', 'Dec 1 2099', '2099', '2026-02-30T00:00:00Z']) {
      for (const label of ['Expiration Time', 'Not Before']) {
        for (const tz of TIME_ZONES) {
          process.env.TZ = tz;
          expectInvalid(() => parseSiweMessage(withLine(label, bad)));
        }
      }
      for (const tz of TIME_ZONES) {
        process.env.TZ = tz;
        const msg = generateSiweMessage(baseParams).replace(
          'Issued At: 2026-07-02T00:00:00.000Z',
          `Issued At: ${bad}`,
        );
        expectInvalid(() => parseSiweMessage(msg));
      }
    }
  });

  it('オフセット付き日時は TZ に依らず同じ UTC ISO 文字列へ正規化される', () => {
    const msg = withLine('Expiration Time', '2026-10-01T21:00:00+09:00');
    for (const tz of TIME_ZONES) {
      process.env.TZ = tz;
      expect(parseSiweMessage(msg).expirationTime).toBe('2026-10-01T12:00:00.000Z');
    }
  });

  it('validateSiweMessage の期限判定は TZ で反転しない', () => {
    const now = new Date('2026-07-02T00:10:00Z');
    const valid = parseSiweMessage(withLine('Expiration Time', '2026-07-02T00:30:00Z'));
    for (const tz of TIME_ZONES) {
      process.env.TZ = tz;
      expect(() => validateSiweMessage(valid, 'example.com', now)).not.toThrow();
    }
  });

  it('validateSiweMessage は手組みのオフセット無し期限を 8041 で拒否する', () => {
    const msg = parseSiweMessage(generateSiweMessage(baseParams));
    for (const tz of TIME_ZONES) {
      process.env.TZ = tz;
      expectInvalid(() =>
        validateSiweMessage({ ...msg, expirationTime: '2099-01-01T00:00:00' }, 'example.com'),
      );
      expectInvalid(() =>
        validateSiweMessage({ ...msg, notBefore: '2020-01-01T00:00:00' }, 'example.com'),
      );
    }
  });
});
