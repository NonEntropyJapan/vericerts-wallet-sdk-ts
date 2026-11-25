/**
 * WUA JWT 解析・検証・WSCD バインド検証のテスト。
 *
 * - WUA 取得（解析）のユニットテスト
 * - Wallet Provider 署名検証 / 期限切れ検知
 * - WSCD バインド検証
 */

import { describe, expect, test } from 'bun:test';
import { VericertsError } from '../../../errors.js';
import { WUA_VCT } from '../types.js';
import {
  isWalletAttestationExpired,
  parseWalletUnitAttestation,
  refreshWalletAttestation,
  verifyWalletUnitAttestation,
  verifyWscdBinding,
} from '../wua.js';
import { makeWuaJwt, OTHER_PRIVATE_KEY, toP256Jwk, WSCD_PRIVATE_KEY } from './wua-fixtures.js';

/** WUA 署名者（Wallet Provider）秘密鍵。fixtures とは独立に固定値を使う。 */
const PROVIDER_KEY = new Uint8Array(32).fill(3);
const PROVIDER_JWK = toP256Jwk(PROVIDER_KEY);
const NOW = 1_712_400_000; // iat < NOW < exp

describe('parseWalletUnitAttestation', () => {
  test('正当な WUA JWT を WalletUnitAttestation へ解析する', () => {
    const jwt = makeWuaJwt(PROVIDER_KEY);
    const wua = parseWalletUnitAttestation(jwt);
    expect(wua.vct).toBe(WUA_VCT);
    expect(wua.walletProviderDID).toBe('https://wallet-provider.example.eu');
    expect(wua.jwt).toBe(jwt);
    expect(wua.issuedAt).toBe(new Date(1_712_345_678 * 1000).toISOString());
    expect(wua.expiresAt).toBe(new Date(1_712_432_078 * 1000).toISOString());
    expect(wua.cnf.jwk).toEqual(toP256Jwk(WSCD_PRIVATE_KEY));
  });

  test('Wallet Provider の DID と ISO 8601 の発行時刻・有効期限を返す', () => {
    // walletProviderId → walletProviderDID への改称、issuedAt/expiresAt の ISO 8601 化、
    // spec 未記載の walletInstanceId 削除を固定する（修正前はこのテストが失敗していた）。
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY)) as unknown as Record<
      string,
      unknown
    >;
    expect(Object.hasOwn(wua, 'walletProviderDID')).toBe(true);
    expect(Object.hasOwn(wua, 'walletProviderId')).toBe(false);
    expect(Object.hasOwn(wua, 'walletInstanceId')).toBe(false);
    expect(typeof wua.issuedAt).toBe('string');
    expect(typeof wua.expiresAt).toBe('string');
    expect(Number.isNaN(Date.parse(wua.issuedAt as string))).toBe(false);
    expect(Number.isNaN(Date.parse(wua.expiresAt as string))).toBe(false);
  });

  test('vct 不正は 10102', () => {
    const jwt = makeWuaJwt(PROVIDER_KEY, { vct: 'urn:eudi:pid:1' });
    expect(() => parseWalletUnitAttestation(jwt)).toThrow(VericertsError);
    try {
      parseWalletUnitAttestation(jwt);
    } catch (e) {
      expect((e as VericertsError).code).toBe('10102');
    }
  });

  test('必須クレーム欠落（cnf なし）は 10102', () => {
    const jwt = makeWuaJwt(PROVIDER_KEY, { cnf: undefined });
    try {
      parseWalletUnitAttestation(jwt);
      throw new Error('should throw');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('10102');
    }
  });

  test('形式不正な JWT は 10102', () => {
    try {
      parseWalletUnitAttestation('not-a-jwt');
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe('10102');
    }
  });

  test('exp が負値・非整数の NumericDate は 10102', () => {
    for (const badExp of [-1, 1.5]) {
      const jwt = makeWuaJwt(PROVIDER_KEY, { exp: badExp });
      try {
        parseWalletUnitAttestation(jwt);
        throw new Error('should throw');
      } catch (e) {
        expect((e as VericertsError).code).toBe('10102');
      }
    }
  });
});

describe('verifyWalletUnitAttestation', () => {
  test('Wallet Provider 署名が正しく期限内なら成功する', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    expect(() => verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW)).not.toThrow();
  });

  test('署名鍵が不一致なら 10102', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const wrongJwk = toP256Jwk(OTHER_PRIVATE_KEY);
    try {
      verifyWalletUnitAttestation(wua, wrongJwk, NOW);
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe('10102');
    }
  });

  test('期限切れは 10103', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const expiresAtSeconds = Math.floor(Date.parse(wua.expiresAt) / 1000);
    try {
      verifyWalletUnitAttestation(wua, PROVIDER_JWK, expiresAtSeconds + 1);
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe('10103');
    }
  });

  test('alg=none 相当（未対応 alg）は 10102', () => {
    // header.alg を差し替えた JWT を組み立てる（署名は無効化される）。
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const [, payloadSeg, sigSeg] = wua.jwt.split('.');
    const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'wua+jwt' })).toString(
      'base64url',
    );
    const tampered = `${noneHeader}.${payloadSeg}.${sigSeg}`;
    const tamperedWua = { ...wua, jwt: tampered };
    try {
      verifyWalletUnitAttestation(tamperedWua, PROVIDER_JWK, NOW);
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe('10102');
    }
  });
});

describe('isWalletAttestationExpired', () => {
  test('exp <= now で期限切れ', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const expiresAtSeconds = Math.floor(Date.parse(wua.expiresAt) / 1000);
    expect(isWalletAttestationExpired(wua, expiresAtSeconds)).toBe(true);
    expect(isWalletAttestationExpired(wua, expiresAtSeconds - 1)).toBe(false);
  });
});

describe('refreshWalletAttestation', () => {
  /** 期限切れ判定用に exp を NOW より過去へ寄せた現行 WUA。 */
  const EXPIRED_EXP = NOW - 10;

  test('期限切れ WUA を再発行 WUA（新 exp・同一 WSCD 鍵）へ差し替える', () => {
    const previous = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY, { exp: EXPIRED_EXP }));
    // 現行 WUA は NOW 時点で期限切れ（10103 の回復対象）。
    expect(isWalletAttestationExpired(previous, NOW)).toBe(true);

    const refreshedJwt = makeWuaJwt(PROVIDER_KEY, { exp: NOW + 86_400 });
    const refreshed = refreshWalletAttestation(previous, refreshedJwt, PROVIDER_JWK, NOW);

    expect(refreshed.jwt).toBe(refreshedJwt);
    expect(refreshed.expiresAt).toBe(new Date((NOW + 86_400) * 1000).toISOString());
    expect(isWalletAttestationExpired(refreshed, NOW)).toBe(false);
    // WSCD 鍵バインドは維持される。
    expect(refreshed.cnf.jwk).toEqual(toP256Jwk(WSCD_PRIVATE_KEY));
  });

  test('再発行 WUA の署名が不正なら 10102', () => {
    const previous = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY, { exp: EXPIRED_EXP }));
    // Provider 以外の鍵で署名された再発行 WUA。
    const refreshedJwt = makeWuaJwt(OTHER_PRIVATE_KEY, { exp: NOW + 86_400 });
    try {
      refreshWalletAttestation(previous, refreshedJwt, PROVIDER_JWK, NOW);
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe('10102');
    }
  });

  test('再発行 WUA も期限切れなら 10103', () => {
    const previous = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY, { exp: EXPIRED_EXP }));
    const refreshedJwt = makeWuaJwt(PROVIDER_KEY, { exp: NOW });
    try {
      refreshWalletAttestation(previous, refreshedJwt, PROVIDER_JWK, NOW);
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe('10103');
    }
  });

  test('再発行 WUA の cnf.jwk が旧 WSCD 鍵と不一致なら 10102', () => {
    const previous = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY, { exp: EXPIRED_EXP }));
    // 別 WSCD 鍵にバインドされた再発行 WUA（鍵すり替え）。
    const refreshedJwt = makeWuaJwt(PROVIDER_KEY, {
      exp: NOW + 86_400,
      cnf: { jwk: toP256Jwk(OTHER_PRIVATE_KEY) },
    });
    try {
      refreshWalletAttestation(previous, refreshedJwt, PROVIDER_JWK, NOW);
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe('10102');
    }
  });
});

describe('verifyWscdBinding', () => {
  test('cnf.jwk が WSCD 鍵に一致すれば成功する', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const wscdJwk = toP256Jwk(WSCD_PRIVATE_KEY);
    expect(() => verifyWscdBinding(wua, wscdJwk)).not.toThrow();
  });

  test('cnf.jwk が WSCD 鍵と不一致なら 10102', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    const otherJwk = toP256Jwk(OTHER_PRIVATE_KEY);
    try {
      verifyWscdBinding(wua, otherJwk);
      throw new Error('should throw');
    } catch (e) {
      expect((e as VericertsError).code).toBe('10102');
    }
  });
});
