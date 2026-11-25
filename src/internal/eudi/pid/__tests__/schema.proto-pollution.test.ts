/**
 * `validatePIDClaims` / `validatePIDSchema` の own 限定読み取りの回帰テスト。
 *
 * 必須属性の存在検査は `claims[attr] === undefined || claims[attr] === null` で行っていたため
 * プロトタイプ鎖を辿り、`Object.prototype.family_name` 等の汚染下では**必須属性を実際に持たない
 * PID でも「存在する」と判定されて Rulebook 検証を通る**（fail-open）。`validatePIDClaims` /
 * `validatePIDSchema` は呼び出し側が組み立てた `PIDClaims` を受け取る公開経路であり、
 * JSON のパースを経由しないため、呼び出し側のオブジェクトを読む箇所でも own-property を確認する。
 *
 * **トートロジー回避**: 汚染値と own 値を食い違わせ、(1) own に無い必須属性は汚染下でも欠落と
 * 報告されること、(2) own にある属性は従来どおり検証されること（汚染で検査対象がすり替わらない
 * こと）の双方を検証する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../__tests__/prototype-pollution.fixtures.js';
import { validatePIDClaims, validatePIDSchema } from '../schema.js';
import { PID_MANDATORY_ATTRIBUTES, type PIDClaims, type PIDCredential } from '../types.js';

/** Rulebook 準拠の必須属性が揃った PID クレーム。 */
function completeClaims(): Record<string, unknown> {
  return {
    family_name: 'Doe',
    given_name: 'Jane',
    birth_date: '1990-01-01',
    issuance_date: '2026-01-01',
    expiry_date: '2036-01-01',
    issuing_authority: 'JP-MIC',
    issuing_country: 'JP',
  };
}

/** 指定した必須属性を落としたクレーム。 */
function claimsWithout(missing: string): Record<string, unknown> {
  const claims = completeClaims();
  delete claims[missing];
  return claims;
}

describe('validatePIDClaims の必須属性検査は own 限定', () => {
  it('family_name を持たない PID は汚染下でも欠落として報告される', () => {
    const claims = claimsWithout('family_name') as unknown as PIDClaims;

    const result = withPollutedPrototype({ family_name: 'Polluted' }, () =>
      validatePIDClaims(claims),
    );

    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.path === 'family_name' && e.required)).toBe(true);
  });

  it('issuing_country を持たない PID は汚染下でも欠落として報告される', () => {
    const claims = claimsWithout('issuing_country') as unknown as PIDClaims;

    const result = withPollutedPrototype({ issuing_country: 'JP' }, () =>
      validatePIDClaims(claims),
    );

    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.path === 'issuing_country' && e.required)).toBe(true);
  });

  it('own に存在する属性は汚染値ですり替わらない（対照。形式検査は元から own のみ）', () => {
    // 形式検査ループは元から `Object.entries`（own かつ列挙可能）で回るため、このケースは
    // 修正前後で挙動が変わらない。own 値が検査対象であることを固定する**対照**として置く。
    const result = withPollutedPrototype({ issuing_country: 'JPN' }, () =>
      validatePIDClaims(completeClaims() as unknown as PIDClaims),
    );

    expect(result.valid).toBe(true);
  });

  it('複数の必須属性を同時に欠く PID も汚染下ですべて欠落として報告される', () => {
    const claims = completeClaims();
    delete claims.given_name;
    delete claims.issuing_authority;

    const result = withPollutedPrototype(
      { given_name: 'Polluted', issuing_authority: 'Polluted-CA' },
      () => validatePIDClaims(claims as unknown as PIDClaims),
    );

    expect(result.valid).toBe(false);
    const paths = (result.errors ?? []).map((e) => e.path);
    expect(paths).toContain('given_name');
    expect(paths).toContain('issuing_authority');
  });

  it('対照: 必須属性が揃っていれば汚染なしでも valid（従来挙動）', () => {
    expect(validatePIDClaims(completeClaims() as unknown as PIDClaims).valid).toBe(true);
  });

  it('対照: 汚染なしで必須属性を欠けば従来どおり欠落として報告される', () => {
    const result = validatePIDClaims(claimsWithout('birth_date') as unknown as PIDClaims);

    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.path === 'birth_date')).toBe(true);
  });
});

describe('validatePIDSchema の claims / vct 読み取りも own 限定', () => {
  /** Rulebook 準拠の PID Credential。 */
  function completeCredential(): Record<string, unknown> {
    return { vct: 'urn:eudi:pid:1', claims: completeClaims() };
  }

  it('vct を own に持たない PID は汚染下でも vct 欠落として拒否される', () => {
    const pid = completeCredential();
    delete pid.vct;

    // 汚染値は正しい PID の vct。鎖読みだとこれが「実測 vct」として照合を通り、
    // **PID ではない資格情報が valid になる**（fail-open）。
    const result = withPollutedPrototype({ vct: 'urn:eudi:pid:1' }, () =>
      validatePIDSchema(pid as unknown as PIDCredential),
    );

    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.path === 'vct')).toBe(true);
  });

  it('claims を own に持たない PID は汚染下でも攻撃者クレームで valid にならない', () => {
    const pid = completeCredential();
    delete pid.claims;

    // 汚染値は Rulebook を満たす完全なクレーム集合。鎖読みだとこれが「実測 claims」として
    // 検証を通り、**クレームを 1 つも持たない PID が valid になる**（fail-open）。
    const result = withPollutedPrototype({ claims: completeClaims() }, () =>
      validatePIDSchema(pid as unknown as PIDCredential),
    );

    expect(result.valid).toBe(false);
    // own に claims が無いので必須属性は**全件**欠落として報告される（1 件だけの検査だと
    // 「たまたま最初の 1 件だけ報告される」実装でも通ってしまう）。
    const paths = (result.errors ?? []).filter((e) => e.required).map((e) => e.path);
    for (const attr of PID_MANDATORY_ATTRIBUTES) {
      expect(paths).toContain(attr);
    }
  });

  it('claims も vct も欠く PID は汚染下で両方が報告される', () => {
    const result = withPollutedPrototype({ vct: 'urn:eudi:pid:1', claims: completeClaims() }, () =>
      validatePIDSchema({} as unknown as PIDCredential),
    );

    expect(result.valid).toBe(false);
    const paths = (result.errors ?? []).map((e) => e.path);
    expect(paths).toContain('vct');
    expect(paths).toContain('birth_date');
  });

  it('対照: own に揃った PID は汚染なしでも汚染下でも valid（正常系を壊さない）', () => {
    expect(validatePIDSchema(completeCredential() as unknown as PIDCredential).valid).toBe(true);

    const underPollution = withPollutedPrototype({ vct: 'urn:attacker:vct' }, () =>
      validatePIDSchema(completeCredential() as unknown as PIDCredential),
    );
    expect(underPollution.valid).toBe(true);
  });

  it('対照: 汚染なしで vct が不正なら従来どおり拒否される', () => {
    const pid = completeCredential();
    pid.vct = 'urn:example:other';

    const result = validatePIDSchema(pid as unknown as PIDCredential);

    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.path === 'vct')).toBe(true);
  });
});

describe('validatePIDSchema の result.errors 読み取りも own 限定', () => {
  /** Rulebook 準拠のクレームを持つが `vct` が PID ではない資格情報。 */
  function nonPidCredential(): Record<string, unknown> {
    return { vct: 'urn:example:other', claims: completeClaims() };
  }

  it('vct 不一致で成功した claims 検証結果に汚染 errors が混入しない', () => {
    // `validatePIDClaims` は claims が Rulebook 準拠なので `{ valid: true }` リテラルを返す。
    // これは own `errors` を持たないため、鎖読みだと `Object.prototype.errors` の汚染値が
    // そのまま返り値へ展開され、**攻撃者が選んだ SchemaError が「検証結果」として返る**。
    const injected = { path: 'family_name', message: 'attacker-controlled', required: false };

    const result = withPollutedPrototype({ errors: [injected] }, () =>
      validatePIDSchema(nonPidCredential() as unknown as PIDCredential),
    );

    expect(result.valid).toBe(false);
    const errors = result.errors ?? [];
    expect(errors).toHaveLength(1);
    expect(errors[0]?.path).toBe('vct');
    expect(errors.some((e) => e.message === 'attacker-controlled')).toBe(false);
  });

  it('非 iterable な errors 汚染でも生の TypeError を投げない（例外を投げない契約）', () => {
    // 鎖読みだと `...result.errors` が非 iterable な汚染値に対して**生の `TypeError`** を投げ、
    // 「例外は投げず結果を返す」契約そのものが破れる。
    const result = withPollutedPrototype({ errors: 42 }, () =>
      validatePIDSchema(nonPidCredential() as unknown as PIDCredential),
    );

    expect(result.valid).toBe(false);
    expect((result.errors ?? []).map((e) => e.path)).toEqual(['vct']);
  });

  it('対照: claims 側にも実エラーがあるときは own の errors が保持される', () => {
    const pid = { vct: 'urn:example:other', claims: claimsWithout('birth_date') };

    const result = withPollutedPrototype({ errors: [{ path: 'injected', message: 'x' }] }, () =>
      validatePIDSchema(pid as unknown as PIDCredential),
    );

    expect(result.valid).toBe(false);
    const paths = (result.errors ?? []).map((e) => e.path);
    expect(paths).toContain('vct');
    expect(paths).toContain('birth_date');
    expect(paths).not.toContain('injected');
  });
});
