/**
 * Entity Statement の有効期間検査が非有限（NaN / ±Infinity）の現在時刻で fail-open しないことの
 * 回帰テスト。
 *
 * 否定形の比較 `now >= exp || now < iat` は NaN で常に `false` になり、期限切れ・発行前 Statement を
 * 通す。修正前はこのテストが落ちる。肯定形（期間内であること）の確認へ改めて fail-closed にする。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { assertStatementTimeValid } from '../../statement/statement.js';
import { LEAF_KEY, NOW_SECONDS, toJwk } from '../federation-fixtures.js';

const ISS = 'https://leaf.example.eu';
const NON_FINITE = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY] as const;
const base = { iss: ISS, sub: ISS, jwks: { keys: [toJwk(LEAF_KEY)] } };
const TRUST_CHAIN_INVALID = new VericertsError(ErrorCodes.TRUST_CHAIN_INVALID);

describe('assertStatementTimeValid: 非有限の nowSeconds は fail-closed', () => {
  it('有限時刻の従来挙動（期間内は通過）', () => {
    expect(() =>
      assertStatementTimeValid(
        { ...base, iat: NOW_SECONDS - 10, exp: NOW_SECONDS + 10 },
        NOW_SECONDS,
      ),
    ).not.toThrow();
  });

  for (const bad of NON_FINITE) {
    it(`nowSeconds = ${bad}: 期限切れ Statement を通さない`, () => {
      const expired = { ...base, iat: NOW_SECONDS - 20, exp: NOW_SECONDS - 10 };
      expect(() => assertStatementTimeValid(expired, bad)).toThrow(TRUST_CHAIN_INVALID);
    });

    it(`nowSeconds = ${bad}: 発行前 Statement を通さない`, () => {
      const notYet = { ...base, iat: NOW_SECONDS + 10, exp: NOW_SECONDS + 20 };
      expect(() => assertStatementTimeValid(notYet, bad)).toThrow(TRUST_CHAIN_INVALID);
    });
  }
});
