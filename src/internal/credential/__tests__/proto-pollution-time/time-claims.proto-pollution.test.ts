/**
 * `assertTimeClaims` の時刻クレーム鎖読みによる時刻検証バイパスの回帰テスト。
 *
 * `assertTimeClaims` は `verifyCredential` / `verifySdJwt` / `verifyPresentation` の
 * **全時刻検証が通る共通経路**である。`const { iat, exp, nbf } = payload` は分割代入であり
 * プロトタイプ鎖を辿るため、これらのクレームを**持たない**正当な payload でも
 * `Object.prototype` の汚染値を拾う。検証対象 payload は `JSON.parse` 由来で
 * `Object.prototype` を継承するため、汚染は素の VC / JWT にそのまま効く。
 *
 * 汚染値の選び方次第で:
 * - `exp` 汚染 → 期限を持たない VC が「期限切れ」に化けて拒否される
 * - `nbf` 汚染 → 「有効化前」として拒否される
 * - `iat` 汚染 → 「クロックスキュー超過」として拒否される
 * - 非数値汚染 → 「時刻型不正」として拒否される
 *
 * いずれも「汚染下でも当該クレームを持たない payload は素通しされる（own 限定読み取り）」を
 * 期待値とする。修正を鎖読み（分割代入）へ戻すと本ファイルの各テストは失敗する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { assertTimeClaims } from '../../time-claims.js';

/** 実時刻（エポック秒）。 */
const NOW = Math.floor(Date.now() / 1000);
/** `vc` 種別の既定クロックスキュー。境界に吸収されない幅を取るために使う。 */
const SKEW = 120;

/**
 * 時刻クレームを一切持たない payload。
 *
 * オブジェクトリテラルなので `Object.prototype` を継承する（`JSON.parse` 由来の payload と同じ）。
 * 汚染キーを own として持たないことが本テストの前提。
 */
function payloadWithoutTimeClaims(): Record<string, unknown> {
  return { iss: 'did:example:issuer', sub: 'did:example:holder' };
}

describe('assertTimeClaims / prototype pollution', () => {
  it('`exp` を持たない payload は `Object.prototype.exp` 汚染下でも期限切れにならない', () => {
    const payload = payloadWithoutTimeClaims();
    expect(Object.hasOwn(payload, 'exp')).toBe(false);

    withPollutedPrototype({ exp: NOW - 100_000 }, () => {
      // 鎖読みだと汚染値 `exp`（十分過去）を拾い VC_EXPIRED(3024) で throw する。
      expect(() => assertTimeClaims(payload, NOW, SKEW)).not.toThrow();
    });
  });

  it('`nbf` を持たない payload は `Object.prototype.nbf` 汚染下でも有効化前にならない', () => {
    const payload = payloadWithoutTimeClaims();
    expect(Object.hasOwn(payload, 'nbf')).toBe(false);

    withPollutedPrototype({ nbf: NOW + 100_000 }, () => {
      // 鎖読みだと汚染値 `nbf`（十分未来）を拾い VC_NOT_YET_VALID(3025) で throw する。
      expect(() => assertTimeClaims(payload, NOW, SKEW)).not.toThrow();
    });
  });

  it('`iat` を持たない payload は `Object.prototype.iat` 汚染下でもスキュー超過にならない', () => {
    const payload = payloadWithoutTimeClaims();
    expect(Object.hasOwn(payload, 'iat')).toBe(false);

    withPollutedPrototype({ iat: NOW + 100_000 }, () => {
      // 鎖読みだと汚染値 `iat`（十分未来）を拾い CLOCK_SKEW_EXCEEDED(4014) で throw する。
      expect(() => assertTimeClaims(payload, NOW, SKEW)).not.toThrow();
    });
  });

  it('時刻クレームを持たない payload は非数値汚染下でも型不正にならない', () => {
    const payload = payloadWithoutTimeClaims();

    withPollutedPrototype({ iat: 'not-a-number', exp: {}, nbf: Number.NaN }, () => {
      // 鎖読みだと汚染値を拾い VC_SCHEMA_INVALID(3002) で throw する。
      expect(() => assertTimeClaims(payload, NOW, SKEW)).not.toThrow();
    });
  });

  it('汚染下でも own の時刻クレームは従来どおり評価される（fail-open にしない）', () => {
    // 汚染値は「受理側」に倒し、own 値の評価が汚染に置き換わっていないことを確かめる。
    withPollutedPrototype({ exp: NOW + 100_000, nbf: NOW - 100_000 }, () => {
      const expired = { ...payloadWithoutTimeClaims(), exp: NOW - 100_000 };
      expect(() => assertTimeClaims(expired, NOW, SKEW)).toThrow();

      const notYetValid = { ...payloadWithoutTimeClaims(), nbf: NOW + 100_000 };
      expect(() => assertTimeClaims(notYetValid, NOW, SKEW)).toThrow();

      const valid = { ...payloadWithoutTimeClaims(), exp: NOW + 100_000, nbf: NOW - 100_000 };
      expect(() => assertTimeClaims(valid, NOW, SKEW)).not.toThrow();
    });
  });
});
