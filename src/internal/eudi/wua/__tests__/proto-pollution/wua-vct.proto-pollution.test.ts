/**
 * `verifyWalletUnitAttestation` / `isWalletAttestationExpired` の own 限定読み取りの回帰テスト
 * （`eudi/pid/schema.ts` の `validatePIDSchema` と同クラス）。
 *
 * `WalletUnitAttestation` は**呼び出し側が組み立てて渡す入力**であり、パース境界
 * を通らないため、鎖読みは 3 つの fail-open を作っていた。
 *
 * - `wua.vct`: own に `vct` を持たない WUA が `Object.prototype.vct` の汚染下で
 *   **型識別子ゲート（`10102`）を素通りする**。
 * - `wua.expiresAt`（`isWalletAttestationExpired` 経由）: own に `expiresAt` を持たない WUA では
 *   **汚染がなくても** `undefined <= now` が false になり、**期限ゲート（`10103`）を素通りする**。
 *   汚染下では攻撃者が選んだ期限が「実測の有効期限」として採られる。`isWalletAttestationExpired`
 *   は独立にエクスポートされた公開 API（リフレッシュ要否の判断）なので単体でも覆う。
 * - `wua.jwt`: own に `jwt` を持たない WUA へ**署名検証の対象そのもの**が汚染値から供給される。
 *
 * **トートロジー回避**: 汚染値と own 値を食い違わせる。対照（正常系）には **own の
 * `expiresAt` / `jwt` / `vct` をすべて備えた WUA** を使う — 備えていない WUA で
 * `not.toThrow()` を主張すると、それ自体が上記の期限 fail-open 経路で緑になり
 * **fail-open を「正常系」として固定してしまう**。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { type WalletUnitAttestation, WUA_VCT } from '../../types.js';
import { isWalletAttestationExpired, verifyWalletUnitAttestation } from '../../wua.js';
import { makeWuaJwt, toP256Jwk, WSCD_PRIVATE_KEY } from '../wua-fixtures.js';

const WUA_FAILED = new VericertsError(ErrorCodes.WUA_VERIFICATION_FAILED);
const WUA_EXPIRED = new VericertsError(ErrorCodes.WUA_LIFETIME_EXPIRED);

/** WUA JWT の payload に合わせた検証時刻（`iat` < now < `exp`）。 */
const NOW = 1_712_400_000;
/** 検証時刻より未来の有効期限（own プロパティとして持たせる、ISO 8601）。 */
const FUTURE_EXPIRY = new Date((NOW + 3_600) * 1000).toISOString();
/** 検証時刻より過去の有効期限（期限切れ = 10103 を期待する、ISO 8601）。 */
const PAST_EXPIRY = new Date((NOW - 1) * 1000).toISOString();

const PROVIDER_JWK = toP256Jwk(WSCD_PRIVATE_KEY);

/** 省略したいキーの指定。 */
interface MakeWuaOptions {
  readonly omit?: readonly string[];
  readonly vct?: string;
  readonly expiresAt?: string;
}

/**
 * すべての必須メンバを own に持つ WUA を組み立て、`omit` で指定したキーだけを落とす。
 *
 * 既定で own の `expiresAt`（未来、ISO 8601）を持たせるのが要点。持たせないと期限ゲートの
 * fail-open で検証が通ってしまい、対照テストが「壊れているから緑」になる。
 */
function makeWua(options: MakeWuaOptions = {}): WalletUnitAttestation {
  const omit = new Set(options.omit ?? []);
  const full: Record<string, unknown> = {
    jwt: makeWuaJwt(WSCD_PRIVATE_KEY),
    vct: options.vct ?? WUA_VCT,
    walletProviderDID: 'https://wallet-provider.example.eu',
    cnf: { jwk: toP256Jwk(WSCD_PRIVATE_KEY) },
    issuedAt: new Date(1_712_345_678 * 1000).toISOString(),
    expiresAt: options.expiresAt ?? FUTURE_EXPIRY,
  };
  const wua: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(full)) {
    if (!omit.has(key)) {
      wua[key] = value;
    }
  }
  return wua as unknown as WalletUnitAttestation;
}

describe('verifyWalletUnitAttestation の vct は own 限定', () => {
  it('vct を own に持たない WUA は汚染下でも 10102 で拒否される', () => {
    const wua = makeWua({ omit: ['vct'] });

    expect(() =>
      // 汚染値は正しい WUA の vct。鎖読みだとこれが「実測 vct」として型識別子ゲートを通る。
      withPollutedPrototype({ vct: WUA_VCT }, () =>
        verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW),
      ),
    ).toThrow(WUA_FAILED);
  });

  it('own の vct が不正なら汚染値では救済されない', () => {
    const wua = makeWua({ vct: 'urn:example:other' });

    expect(() =>
      withPollutedPrototype({ vct: WUA_VCT }, () =>
        verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW),
      ),
    ).toThrow(WUA_FAILED);
  });

  it('対照: own に正しい vct と未来の expiresAt があれば汚染下でも検証を通る', () => {
    const wua = makeWua();

    expect(() =>
      withPollutedPrototype({ vct: 'urn:attacker:vct' }, () =>
        verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW),
      ),
    ).not.toThrow();
  });

  it('対照: 汚染なしで own メンバが揃っていれば検証を通る（正常系を壊さない）', () => {
    expect(() => verifyWalletUnitAttestation(makeWua(), PROVIDER_JWK, NOW)).not.toThrow();
  });
});

describe('verifyWalletUnitAttestation の期限・JWT も own 限定', () => {
  it('expiresAt を own に持たない WUA は汚染なしでも 10103 で拒否される', () => {
    // 従来は `undefined <= NOW` が false になり**期限ゲートを素通り**していた（fail-open）。
    const wua = makeWua({ omit: ['expiresAt'] });

    expect(() => verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW)).toThrow(WUA_EXPIRED);
  });

  it('expiresAt を own に持たない WUA は汚染下でも 10103 で拒否される', () => {
    const wua = makeWua({ omit: ['expiresAt'] });

    expect(() =>
      withPollutedPrototype({ expiresAt: FUTURE_EXPIRY }, () =>
        verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW),
      ),
    ).toThrow(WUA_EXPIRED);
  });

  it('own の expiresAt が過去なら従来どおり 10103（期限検査が生きている対照）', () => {
    const wua = makeWua({ expiresAt: PAST_EXPIRY });

    expect(() => verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW)).toThrow(WUA_EXPIRED);
  });

  it('own の expiresAt が過去なら汚染値（未来）では救済されない', () => {
    const wua = makeWua({ expiresAt: PAST_EXPIRY });

    expect(() =>
      withPollutedPrototype({ expiresAt: FUTURE_EXPIRY }, () =>
        verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW),
      ),
    ).toThrow(WUA_EXPIRED);
  });

  it('jwt を own に持たない WUA は汚染下でも 10102 で拒否される（署名対象を汚染値から採らない）', () => {
    const wua = makeWua({ omit: ['jwt'] });

    expect(() =>
      withPollutedPrototype({ jwt: makeWuaJwt(WSCD_PRIVATE_KEY) }, () =>
        verifyWalletUnitAttestation(wua, PROVIDER_JWK, NOW),
      ),
    ).toThrow(WUA_FAILED);
  });
});

describe('isWalletAttestationExpired は own 限定（公開 API）', () => {
  it('expiresAt を own に持たなければ汚染なしでも期限切れ扱い（fail-closed）', () => {
    expect(isWalletAttestationExpired(makeWua({ omit: ['expiresAt'] }), NOW)).toBe(true);
  });

  it('expiresAt を own に持たなければ汚染下でも期限切れ扱い', () => {
    const wua = makeWua({ omit: ['expiresAt'] });

    const expired = withPollutedPrototype({ expiresAt: FUTURE_EXPIRY }, () =>
      isWalletAttestationExpired(wua, NOW),
    );

    expect(expired).toBe(true);
  });

  it('expiresAt が ISO 8601 として解釈できなければ期限切れ扱い（判定不能を「有効」に倒さない）', () => {
    const wua = makeWua({ omit: ['expiresAt'] }) as unknown as Record<string, unknown>;
    wua.expiresAt = 'not-a-date';

    expect(isWalletAttestationExpired(wua as unknown as WalletUnitAttestation, NOW)).toBe(true);
  });

  it('expiresAt が数値（旧形状）でも期限切れ扱い（型不正、判定不能を「有効」に倒さない）', () => {
    const wua = makeWua({ omit: ['expiresAt'] }) as unknown as Record<string, unknown>;
    wua.expiresAt = NOW + 3_600;

    expect(isWalletAttestationExpired(wua as unknown as WalletUnitAttestation, NOW)).toBe(true);
  });

  it('対照: own の expiresAt が未来なら有効、過去なら期限切れ', () => {
    expect(isWalletAttestationExpired(makeWua(), NOW)).toBe(false);
    expect(isWalletAttestationExpired(makeWua({ expiresAt: PAST_EXPIRY }), NOW)).toBe(true);
  });

  it('対照: own の expiresAt が未来なら汚染値（過去）で期限切れにされない', () => {
    const wua = makeWua();

    const expired = withPollutedPrototype({ expiresAt: PAST_EXPIRY }, () =>
      isWalletAttestationExpired(wua, NOW),
    );

    expect(expired).toBe(false);
  });
});
