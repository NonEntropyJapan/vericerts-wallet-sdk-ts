/**
 * WUA JWT クレームの鎖読みによる repack バイパスの回帰テスト。
 *
 * `parseWalletUnitAttestation` は `payload` から読んだクレームを**戻り値の own プロパティへ
 * 詰め直す**。したがってクレームを鎖読みすると、`own-property.ts` が警告する repack パターン
 * そのものになり、`verifyWscdBinding` / `isWalletAttestationExpired` など下流の own 限定読み取りが
 * 丸ごと無効化される（汚染値と正当な値が区別できなくなる）。
 *
 * 具体的な破れ:
 * - `cnf`: `cnf` を持たない WUA が `Object.prototype.cnf` の攻撃者鍵にバインドされ、WSCD /
 *   device binding が完全にバイパスされる（WUA-PoP が攻撃者鍵で生成できる）。
 * - `exp`: `exp` を持たない WUA が遠い未来の期限として受理され、期限切れ検知が永久に効かない。
 * - `iss`: `walletProviderDID` が攻撃者の選んだ Wallet Provider に化ける。
 *
 * `refreshWalletAttestation` は照合の**基準側**（旧 WUA の `cnf.jwk`）を渡すため、渡す前が
 * 鎖読みだと `verifyWscdBinding` 内部の own 化が効かない。
 *
 * 期待値は「当該クレームを own に持たない WUA は汚染下でも `10102` で拒否される」。
 * 修正を鎖読みへ戻すと本ファイルの各テストは失敗する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import type { WalletUnitAttestation } from '../../types.js';
import { WUA_VCT } from '../../types.js';
import { parseWalletUnitAttestation, refreshWalletAttestation } from '../../wua.js';
import { makeWuaJwt, OTHER_PRIVATE_KEY, toP256Jwk, WSCD_PRIVATE_KEY } from '../wua-fixtures.js';

const PROVIDER_KEY = new Uint8Array(32).fill(3);
const PROVIDER_JWK = toP256Jwk(PROVIDER_KEY);
const NOW = 1_712_400_000; // iat < NOW < exp
const WSCD_JWK = toP256Jwk(WSCD_PRIVATE_KEY);
/** 攻撃者が握る鍵（WSCD 鍵とは別物）。 */
const ATTACKER_JWK = toP256Jwk(OTHER_PRIVATE_KEY);

/** 10102 で拒否されることを表明する。 */
function expectWuaRejected(fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(ErrorCodes.WUA_VERIFICATION_FAILED);
    return;
  }
  throw new Error('汚染下で素通りした（fail-open）');
}

describe('parseWalletUnitAttestation / prototype pollution', () => {
  it('正常系: 全クレームを own に持つ WUA は従来どおり解析される', () => {
    const wua = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY));
    expect(wua.walletProviderDID).toBe('https://wallet-provider.example.eu');
    expect(wua.cnf.jwk).toEqual(WSCD_JWK);
  });

  it('`cnf` を持たない WUA は汚染下でも攻撃者鍵にバインドされない', () => {
    // `cnf: undefined` は JSON.stringify で落ちるため、payload は `cnf` を own に持たない。
    const jwt = makeWuaJwt(PROVIDER_KEY, { cnf: undefined });
    withPollutedPrototype({ cnf: { jwk: ATTACKER_JWK } }, () => {
      // 鎖読みだと汚染 `cnf` が戻り値の own プロパティへ詰め直され、以降 WSCD バインド検査が
      // 攻撃者鍵で成立する（`verifyWscdBinding` の own 化が無効化される）。
      expectWuaRejected(() => parseWalletUnitAttestation(jwt));
    });
  });

  it('`cnf.jwk` を持たない WUA も汚染下で攻撃者鍵にバインドされない', () => {
    const jwt = makeWuaJwt(PROVIDER_KEY, { cnf: {} });
    withPollutedPrototype({ jwk: ATTACKER_JWK }, () => {
      expectWuaRejected(() => parseWalletUnitAttestation(jwt));
    });
  });

  it('`exp` を持たない WUA は汚染下でも遠い未来の期限を得ない', () => {
    const jwt = makeWuaJwt(PROVIDER_KEY, { exp: undefined });
    withPollutedPrototype({ exp: 9_999_999_999 }, () => {
      // 鎖読みだと `isWalletAttestationExpired` が永久に false を返す WUA が成立する。
      expectWuaRejected(() => parseWalletUnitAttestation(jwt));
    });
  });

  it('`iat` を持たない WUA は汚染下でも受理されない', () => {
    const jwt = makeWuaJwt(PROVIDER_KEY, { iat: undefined });
    withPollutedPrototype({ iat: 1_712_345_678 }, () => {
      expectWuaRejected(() => parseWalletUnitAttestation(jwt));
    });
  });

  it('`iss` を持たない WUA は汚染下でも `walletProviderDID` を攻撃者に握られない', () => {
    const jwt = makeWuaJwt(PROVIDER_KEY, { iss: undefined });
    withPollutedPrototype({ iss: 'https://evil.example' }, () => {
      expectWuaRejected(() => parseWalletUnitAttestation(jwt));
    });
  });

  it('`sub` を持たない WUA は汚染下でも構造検査（必須クレーム）を素通りしない', () => {
    // `WalletUnitAttestation` 自体は `sub` を `walletInstanceId` として持たないが、
    // `sub` は WUA JWT の必須クレームであり続けるため、欠落は汚染下でも拒否されなければならない。
    const jwt = makeWuaJwt(PROVIDER_KEY, { sub: undefined });
    withPollutedPrototype({ sub: 'urn:uuid:attacker' }, () => {
      expectWuaRejected(() => parseWalletUnitAttestation(jwt));
    });
  });

  it('`vct` を持たない WUA は汚染下でも型検査を素通りしない', () => {
    const jwt = makeWuaJwt(PROVIDER_KEY, { vct: undefined });
    withPollutedPrototype({ vct: WUA_VCT }, () => {
      expectWuaRejected(() => parseWalletUnitAttestation(jwt));
    });
  });
});

describe('refreshWalletAttestation / prototype pollution', () => {
  const EXPIRED_EXP = NOW - 10;

  it('正常系: 同一 WSCD 鍵の再発行 WUA は従来どおり受理される', () => {
    const previous = parseWalletUnitAttestation(makeWuaJwt(PROVIDER_KEY, { exp: EXPIRED_EXP }));
    const refreshedJwt = makeWuaJwt(PROVIDER_KEY, { exp: NOW + 86_400 });
    expect(refreshWalletAttestation(previous, refreshedJwt, PROVIDER_JWK, NOW).jwt).toBe(
      refreshedJwt,
    );
  });

  it('`cnf` を own に持たない旧 WUA は汚染下でも照合の基準にならない', () => {
    // 旧 WUA から `cnf` を own から外す（継承値だけが見える状態）。
    const full = parseWalletUnitAttestation(
      makeWuaJwt(PROVIDER_KEY, { exp: EXPIRED_EXP }),
    ) as unknown as Record<string, unknown>;
    const previous: Record<string, unknown> = {};
    for (const key of Object.keys(full)) {
      if (key !== 'cnf') {
        previous[key] = full[key];
      }
    }
    // 再発行 WUA は**攻撃者鍵**にバインドされている（WSCD 鍵の差し替え）。
    const refreshedJwt = makeWuaJwt(PROVIDER_KEY, { exp: NOW + 86_400 }, { cnfJwk: ATTACKER_JWK });
    withPollutedPrototype({ cnf: { jwk: ATTACKER_JWK } }, () => {
      // 鎖読みで `previous.cnf.jwk` を渡すと汚染値が基準になり、鍵すり替えが「一致」になる。
      expectWuaRejected(() =>
        refreshWalletAttestation(
          previous as unknown as WalletUnitAttestation,
          refreshedJwt,
          PROVIDER_JWK,
          NOW,
        ),
      );
    });
  });

  it('`cnf.jwk` を own に持たない旧 WUA も汚染下で照合の基準にならない', () => {
    const previous = parseWalletUnitAttestation(
      makeWuaJwt(PROVIDER_KEY, { exp: EXPIRED_EXP }),
    ) as unknown as Record<string, unknown>;
    previous.cnf = {};
    const refreshedJwt = makeWuaJwt(PROVIDER_KEY, { exp: NOW + 86_400 }, { cnfJwk: ATTACKER_JWK });
    withPollutedPrototype({ jwk: ATTACKER_JWK as unknown as PublicKeyJwk }, () => {
      expectWuaRejected(() =>
        refreshWalletAttestation(
          previous as unknown as WalletUnitAttestation,
          refreshedJwt,
          PROVIDER_JWK,
          NOW,
        ),
      );
    });
  });
});
