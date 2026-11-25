import { describe, expect, test } from 'bun:test';
import { modulusToLimbs, planActionsForIdp } from './monitor-core.mjs';

describe('modulusToLimbs の範囲検査', () => {
  const toN = (value) =>
    Buffer.from(
      value
        .toString(16)
        .padStart(2, '0')
        .replace(/^(?=(?:..)*.$)/, '0'),
      'hex',
    ).toString('base64url');

  test('regression: 2057bit を超える modulus（4096bit 鍵など）は切り詰めずエラーにする', () => {
    expect(() => modulusToLimbs(toN((1n << 4095n) | 0xdeadbeefn))).toThrow(/を超えている/);
    expect(() => modulusToLimbs(toN(1n << 2057n))).toThrow(/を超えている/);
  });

  test('regression: 2057bit ちょうど（17 limb 満杯）までは受理し可逆', () => {
    const max = (1n << 2057n) - 1n;
    const limbs = modulusToLimbs(toN(max));
    expect(limbs.reduce((acc, limb, i) => acc + (limb << (121n * BigInt(i))), 0n)).toBe(max);
  });

  test('regression: modulus が 0 / 空ならエラーにする', () => {
    expect(() => modulusToLimbs('')).toThrow(/0 または空/);
    expect(() => modulusToLimbs('AAAA')).toThrow(/0 または空/);
  });

  test('regression: planActionsForIdp は非対応サイズの鍵が 1 件でもあれば IdP 単位で失敗する', async () => {
    const chainClient = {
      getModulusStatus: async () => ({ registered: false }),
      getRegisteredEvents: async () => [],
      getKey: async () => ({ notAfter: 0n, revoked: false, registered: true }),
    };
    await expect(
      planActionsForIdp({
        idp: { iss: 'https://issuer.example' },
        jwksKeys: [
          { kid: 'ok', n: toN((1n << 2047n) | 1n) },
          { kid: 'big', n: toN((1n << 4095n) | 0xdeadbeefn) },
        ],
        chainClient,
        now: 1000n,
      }),
    ).rejects.toThrow(/kid=big/);
  });
});
