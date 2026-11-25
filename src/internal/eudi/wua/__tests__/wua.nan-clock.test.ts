/**
 * WUA 期限判定が非有限（NaN / ±Infinity）の現在時刻で fail-open しないことの回帰テスト。
 *
 * `expiresAtMs <= nowSeconds * 1000` は NaN で常に `false` になり、期限切れ WUA を「有効」と判定して
 * `verifyWalletUnitAttestation` が受理する。修正前はこのテストが落ちる。判定不能は期限切れへ倒す。
 */

import { describe, expect, test } from 'bun:test';
import type { VericertsError } from '../../../errors.js';
import {
  isWalletAttestationExpired,
  parseWalletUnitAttestation,
  verifyWalletUnitAttestation,
} from '../wua.js';
import { makeWuaJwt, toP256Jwk } from './wua-fixtures.js';

const PROVIDER_KEY = new Uint8Array(32).fill(3);
const PROVIDER_JWK = toP256Jwk(PROVIDER_KEY);
const NON_FINITE = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY] as const;

describe('isWalletAttestationExpired: 非有限の nowSeconds は期限切れ扱い', () => {
  const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
  const expiresAtSeconds = Math.floor(Date.parse(wua.expiresAt) / 1000);

  test('有限時刻の従来挙動（期限内は false / 期限後は true）', () => {
    expect(isWalletAttestationExpired(wua, expiresAtSeconds - 1)).toBe(false);
    expect(isWalletAttestationExpired(wua, expiresAtSeconds + 1)).toBe(true);
  });

  for (const bad of NON_FINITE) {
    test(`nowSeconds = ${bad}: 期限切れ（true）`, () => {
      expect(isWalletAttestationExpired(wua, bad)).toBe(true);
    });

    test(`nowSeconds = ${bad}: verifyWalletUnitAttestation は 10103 で拒否する`, () => {
      try {
        verifyWalletUnitAttestation(wua, PROVIDER_JWK, bad);
        throw new Error('should throw');
      } catch (e) {
        expect((e as VericertsError).code).toBe('10103');
      }
    });
  }
});
