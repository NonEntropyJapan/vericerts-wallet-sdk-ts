/**
 * statement.ts（Entity Statement のデコード・構造検証・署名検証プリミティブ）のユニットテスト。
 * 実鍵 P-256 で署名。
 *
 * 検証内容:
 * - decodeAndVerifyStatement: 正しい鍵で成功、別鍵で TRUST_CHAIN_INVALID、kid 選択（不一致は拒否）、
 *   未対応 alg 拒否。
 * - parseEntityStatement: 必須クレーム欠落・型不正の拒否、任意クレームの引き継ぎ。
 * - assertStatementTimeValid: 期限切れ / 発行前の拒否。
 * - decodeStatementJws / selfJwksOf: 形式不正の拒否。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import {
  assertStatementTimeValid,
  decodeAndVerifyStatement,
  decodeStatementJws,
  MAX_JWKS_KEYS,
  parseEntityStatement,
  selfJwksOf,
} from '../../statement/statement.js';
import {
  INTERMEDIATE_KEY,
  LEAF_KEY,
  NOW_SECONDS,
  signStatement,
  toJwk,
  validPeriod,
} from '../federation-fixtures.js';

/** 例外が指定コードの VericertsError であることを検証する。 */
function expectThrowCode(fn: () => unknown, code: ErrorCode): void {
  let caught: unknown;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(code);
}

const ISS = 'https://leaf.example.eu';

describe('decodeAndVerifyStatement', () => {
  it('正しい鍵集合で署名検証・構造検証に成功する', () => {
    const jwks = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };
    const jwt = signStatement(
      LEAF_KEY,
      { iss: ISS, sub: ISS, ...validPeriod(), jwks },
      { kid: 'leaf-1' },
    );
    const statement = decodeAndVerifyStatement(jwt, jwks);
    expect(statement.iss).toBe(ISS);
    expect(statement.jwks.keys.length).toBe(1);
  });

  it('署名鍵に対応しない鍵集合では TRUST_CHAIN_INVALID', () => {
    const signingJwks = { keys: [toJwk(LEAF_KEY)] };
    const jwt = signStatement(LEAF_KEY, {
      iss: ISS,
      sub: ISS,
      ...validPeriod(),
      jwks: signingJwks,
    });
    const wrongJwks = { keys: [toJwk(INTERMEDIATE_KEY)] };
    expectThrowCode(() => decodeAndVerifyStatement(jwt, wrongJwks), ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('header.kid が JWKS に無ければ、別の鍵で署名が成立しても TRUST_CHAIN_INVALID', () => {
    // 署名は LEAF_KEY、header.kid は JWKS に存在しない kid。jwks には署名鍵そのもの（別 kid）が
    // 入っているため、全鍵フォールバックがあると「通ってしまう」構図。発行者が指名していない鍵で
    // 受理しないことを固定する（回帰: kid 不一致時の全鍵フォールバック）。
    const jwks = { keys: [toJwk(LEAF_KEY, 'actual-kid')] };
    const jwt = signStatement(
      LEAF_KEY,
      { iss: ISS, sub: ISS, ...validPeriod(), jwks },
      { kid: 'nonexistent-kid' },
    );
    expectThrowCode(() => decodeAndVerifyStatement(jwt, jwks), ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('header.kid 無しなら JWKS の全鍵を試す', () => {
    // kid を指名していない Statement は従来どおり全鍵試行で検証できる（上の厳格化の巻き添えで
    // 壊れていないことを固定する）。
    const jwks = { keys: [toJwk(INTERMEDIATE_KEY, 'int-1'), toJwk(LEAF_KEY, 'leaf-1')] };
    const jwt = signStatement(LEAF_KEY, { iss: ISS, sub: ISS, ...validPeriod(), jwks });
    expect(decodeAndVerifyStatement(jwt, jwks).iss).toBe(ISS);
  });

  it('kid 無しで鍵数が MAX_JWKS_KEYS ちょうどなら末尾の署名鍵でも検証できる', () => {
    const decoys = Array.from({ length: MAX_JWKS_KEYS - 1 }, () => toJwk(INTERMEDIATE_KEY));
    const jwks = { keys: [...decoys, toJwk(LEAF_KEY)] };
    const jwt = signStatement(LEAF_KEY, { iss: ISS, sub: ISS, ...validPeriod(), jwks });
    expect(decodeAndVerifyStatement(jwt, selfJwksOf(decodeStatementJws(jwt))).iss).toBe(ISS);
  });

  it('jwks.keys が MAX_JWKS_KEYS + 1 件の Statement は署名検証前（鍵抽出）で TRUST_CHAIN_INVALID', () => {
    // 鍵数に上限が無いと kid 無しヘッダで全鍵を ECDSA 検証してしまう。鍵集合のサイズだけで
    // 拒否されること（decoy は中身を持たない `{}` で、検証に進めば別経路の失敗になる）を固定する。
    const jwks = { keys: [...Array.from({ length: MAX_JWKS_KEYS }, () => ({})), toJwk(LEAF_KEY)] };
    const jwt = signStatement(LEAF_KEY, { iss: ISS, sub: ISS, ...validPeriod(), jwks });
    expectThrowCode(() => selfJwksOf(decodeStatementJws(jwt)), ErrorCodes.TRUST_CHAIN_INVALID);
    expectThrowCode(
      () => parseEntityStatement({ iss: ISS, sub: ISS, iat: 1, exp: 2, jwks }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('未対応 alg（RS256）は TRUST_CHAIN_INVALID', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ iss: ISS, sub: ISS, ...validPeriod(), jwks: { keys: [toJwk(LEAF_KEY)] } }),
    ).toString('base64url');
    const jwt = `${header}.${payload}.AAAA`;
    expectThrowCode(
      () => decodeAndVerifyStatement(jwt, { keys: [toJwk(LEAF_KEY)] }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('3 セグメントでない JWT は TRUST_CHAIN_INVALID', () => {
    expectThrowCode(
      () => decodeAndVerifyStatement('a.b', { keys: [toJwk(LEAF_KEY)] }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });
});

describe('parseEntityStatement', () => {
  it('必須クレーム欠落（iss なし）は TRUST_CHAIN_INVALID', () => {
    expectThrowCode(
      () => parseEntityStatement({ sub: ISS, iat: 1, exp: 2, jwks: { keys: [{}] } }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('iat / exp が数値でないと TRUST_CHAIN_INVALID', () => {
    expectThrowCode(
      () => parseEntityStatement({ iss: ISS, sub: ISS, iat: 'x', exp: 2, jwks: { keys: [{}] } }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('jwks.keys が空配列だと TRUST_CHAIN_INVALID', () => {
    expectThrowCode(
      () => parseEntityStatement({ iss: ISS, sub: ISS, iat: 1, exp: 2, jwks: { keys: [] } }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('authority_hints に非文字列が混ざると TRUST_CHAIN_INVALID', () => {
    expectThrowCode(
      () =>
        parseEntityStatement({
          iss: ISS,
          sub: ISS,
          iat: 1,
          exp: 2,
          jwks: { keys: [{}] },
          authority_hints: ['https://a', 42],
        }),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('任意クレーム（metadata / metadata_policy / authority_hints）を引き継ぐ', () => {
    const statement = parseEntityStatement({
      iss: ISS,
      sub: ISS,
      iat: 1,
      exp: 2,
      jwks: { keys: [{}] },
      authority_hints: ['https://a'],
      metadata: { federation_entity: { federation_fetch_endpoint: 'https://a/fetch' } },
      metadata_policy: { openid_provider: {} },
    });
    expect(statement.authority_hints).toEqual(['https://a']);
    expect(statement.metadata?.federation_entity?.federation_fetch_endpoint).toBe(
      'https://a/fetch',
    );
    expect(statement.metadata_policy).toEqual({ openid_provider: {} });
  });
});

describe('assertStatementTimeValid', () => {
  const base = {
    iss: ISS,
    sub: ISS,
    jwks: { keys: [toJwk(LEAF_KEY)] },
  };

  it('有効期間内は通過する', () => {
    expect(() =>
      assertStatementTimeValid(
        { ...base, iat: NOW_SECONDS - 10, exp: NOW_SECONDS + 10 },
        NOW_SECONDS,
      ),
    ).not.toThrow();
  });

  it('期限切れ（now >= exp）は TRUST_CHAIN_INVALID', () => {
    expectThrowCode(
      () =>
        assertStatementTimeValid(
          { ...base, iat: NOW_SECONDS - 20, exp: NOW_SECONDS - 10 },
          NOW_SECONDS,
        ),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });

  it('発行前（now < iat）は TRUST_CHAIN_INVALID', () => {
    expectThrowCode(
      () =>
        assertStatementTimeValid(
          { ...base, iat: NOW_SECONDS + 10, exp: NOW_SECONDS + 20 },
          NOW_SECONDS,
        ),
      ErrorCodes.TRUST_CHAIN_INVALID,
    );
  });
});

describe('decodeStatementJws / selfJwksOf', () => {
  it('payload の jwks を取り出す', () => {
    const jwks = { keys: [toJwk(LEAF_KEY, 'leaf-1')] };
    const jwt = signStatement(LEAF_KEY, { iss: ISS, sub: ISS, ...validPeriod(), jwks });
    expect(selfJwksOf(decodeStatementJws(jwt)).keys.length).toBe(1);
  });

  it('jwks 欠落は TRUST_CHAIN_INVALID', () => {
    const jwt = signStatement(LEAF_KEY, { iss: ISS, sub: ISS, ...validPeriod() });
    expectThrowCode(() => selfJwksOf(decodeStatementJws(jwt)), ErrorCodes.TRUST_CHAIN_INVALID);
  });

  it('base64url / JSON 不正 payload は TRUST_CHAIN_INVALID', () => {
    expectThrowCode(() => decodeStatementJws('aaa.!!!.bbb'), ErrorCodes.TRUST_CHAIN_INVALID);
  });
});
