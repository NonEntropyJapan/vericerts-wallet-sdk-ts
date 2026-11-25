/**
 * `validateStatus` の own 読み取りと、own **アクセサ**に対する 1 度読みの回帰テスト。
 *
 * 同 Issue の `validateCnf` 本体（`cnf.jwk` の own 読み取り・パース境界）は
 * `cnf-jwk.proto-pollution.test.ts` にある。Linterly のファイル行数上限（300 行）に収めるため、
 * 同じ `claims.ts` を対象とする以下の 2 面をこちらへ分けた:
 *
 * 1. `validateStatus` の `status_list` / `idx` / `uri` の own 読み取り（`validateCnf` と同クラス。
 *    鎖読みだと own の `{}` を持つ `status` が `Object.prototype.status_list` 汚染下で継承値を拾い、
 *    **攻撃者が選んだ status list URI** が下流の `resolveStatus` / `resolver.resolve` へ渡る）。
 * 2. own アクセサによる TOCTOU（`Object.prototype` 汚染とは別の面）。検証と戻り値で元オブジェクトを
 *    **二度読む**と、own の getter は呼ばれるたびに別の値を返せるため「検証を通った値」と「呼び出し元へ
 *    返る値」が食い違う。`ownDataSnapshot` が読み取りを 1 回に固定していることを、getter の呼び出し
 *    回数と戻り値の内容の両方で検証する。
 *
 * 汚染は共有フィクスチャ `internal/__tests__/prototype-pollution.fixtures.ts` の
 * `withPollutedPrototype` で仕込む（非列挙・必ず復元）。**汚染値は own 値と必ず食い違わせる**。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { validateCnf, validateStatus } from '../../claims.js';

/** Holder の Ed25519 公開鍵座標（32 byte）。`validateCnf` は形状のみ見るため実鍵である必要はない。 */
const HOLDER_X = Buffer.from(new Uint8Array(32).fill(3)).toString('base64url');

/** RFC 8037 準拠の正当な Ed25519 JWK（`y` を持たない）。 */
const OKP_JWK = { kty: 'OKP', crv: 'Ed25519', x: HOLDER_X } as const;

/** 汚染下で `validateStatus` を直接実行し、成功値か送出された例外のどちらかを返す。 */
function statusUnderPollution(
  props: Readonly<Record<string, unknown>>,
  value: unknown,
): { ok: true; status: unknown } | { ok: false; error: unknown } {
  return withPollutedPrototype(props, () => {
    try {
      return { ok: true as const, status: validateStatus(value) };
    } catch (error) {
      return { ok: false as const, error };
    }
  });
}

/** 攻撃者が仕込む status list 参照（own 値と必ず食い違わせる）。 */
const EVIL_STATUS_LIST = { idx: 42, uri: 'https://attacker.example/status' } as const;
const OWN_STATUS_LIST = { idx: 7, uri: 'https://issuer.example/status' } as const;

describe('claims.ts: validateStatus の own 読み取り（validateCnf と同クラス）', () => {
  it('status_list を持たない status は Object.prototype.status_list 汚染下でも拒否される', () => {
    // 鎖読みだと own の `{}` が継承値を拾って形状検証を通過し、**攻撃者が選んだ status list URI**
    // が下流の `resolveStatus` / `resolver.resolve` へ渡る（fail-open）。
    const outcome = statusUnderPollution({ status_list: { ...EVIL_STATUS_LIST } }, {});
    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? null : outcome.error).toEqual(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('idx / uri を持たない status_list は汚染下でも拒否される', () => {
    const outcome = statusUnderPollution({ ...EVIL_STATUS_LIST }, { status_list: {} });
    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? null : outcome.error).toEqual(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('own の status_list は汚染を shadow する（汚染値ではなく own の idx / uri を返す）', () => {
    const outcome = statusUnderPollution(
      { status_list: { ...EVIL_STATUS_LIST } },
      {
        status_list: { ...OWN_STATUS_LIST },
      },
    );
    expect(outcome.ok).toBe(true);
    expect(outcome.ok ? outcome.status : null).toEqual({ status_list: { ...OWN_STATUS_LIST } });
  });

  it('汚染下でも status 未設定なら undefined のまま返る（退行しない）', () => {
    const outcome = statusUnderPollution({ status_list: { ...EVIL_STATUS_LIST } }, undefined);
    expect(outcome.ok).toBe(true);
    expect(outcome.ok ? outcome.status : 'thrown').toBeUndefined();
  });

  it('対照: 汚染が無ければ正当な status は従来どおり受理される', () => {
    expect(validateStatus({ status_list: { ...OWN_STATUS_LIST } })).toEqual({
      status_list: { ...OWN_STATUS_LIST },
    });
  });
});

describe('claims.ts: validateCnf の戻り値は own メンバを保全する', () => {
  it('kid など検証対象外の own メンバは落とさずに返す', () => {
    // 検証済みの kty / crv / x / y だけで組み直すと `kid` が黙って消え、公開 API の戻り値が退行する。
    // own メンバを列挙可否を問わず写す形（`ownDataSnapshot`）なら、鎖を断ちつつ `kid` を保全できる。
    // `Object.assign` 等の「列挙可能 own のみ」の複製へ置き換えると、下の非列挙 own の保全が落ちる。
    const result = validateCnf({ jwk: { ...OKP_JWK, kid: 'holder-key-1' } }, false);
    const jwk = (result as { jwk: Record<string, unknown> }).jwk;
    expect(jwk.kid).toBe('holder-key-1');
    expect(jwk.x).toBe(HOLDER_X);
    expect(Object.getPrototypeOf(jwk)).toBeNull();
  });
});

/**
 * own **アクセサ**を使った TOCTOU の回帰テスト。
 *
 * `Object.prototype` 汚染とは別の面。`validateCnf` が検証と戻り値で元オブジェクトを**二度読む**と、
 * own の getter は呼ばれるたびに別の値を返せるため「検証を通った値」と「呼び出し元へ返る値」が
 * 食い違う。`ownDataSnapshot` で読み取りを 1 回に固定していることを、getter の呼び出し回数と
 * 戻り値の内容の両方で検証する。
 */
describe('claims.ts: own アクセサに対する 1 度読み', () => {
  /** n 回目の呼び出しで `values[n-1]` を返す own getter を持つ JWK を作る。 */
  function jwkWithGetter(
    base: Readonly<Record<string, unknown>>,
    key: string,
    values: readonly unknown[],
  ): { jwk: Record<string, unknown>; calls: { count: number } } {
    const calls = { count: 0 };
    const jwk: Record<string, unknown> = { ...base };
    Object.defineProperty(jwk, key, {
      get() {
        const value = values[Math.min(calls.count, values.length - 1)];
        calls.count += 1;
        return value;
      },
      enumerable: true,
      configurable: true,
    });
    return { jwk, calls };
  }

  it('OKP の `y` getter が「1 回目 undefined / 2 回目 注入値」でも注入値を返さない', () => {
    // 二度読みだと、検証時は `y === undefined`（OKP として受理）→ 戻り値の複製時に 'INJECTED' を
    // 拾い、OKP なのに `y` を持つ ConfirmationClaim が公開 API と `verifyWithJwk` へ流れる。
    const { jwk, calls } = jwkWithGetter(OKP_JWK, 'y', [undefined, 'INJECTED']);
    const result = validateCnf({ jwk }, false);
    expect((result as { jwk: Record<string, unknown> }).jwk.y).toBeUndefined();
    expect(calls.count).toBe(1);
  });

  it('`crv` getter が 2 回目に鍵合意専用曲線を返しても戻り値は検証済みの曲線のまま', () => {
    // 二度読みだと `SIGNING_CRVS_BY_KTY` の許可検査を通っていない X25519 が戻り値に載る。
    const { jwk, calls } = jwkWithGetter({ kty: 'OKP', x: HOLDER_X }, 'crv', ['Ed25519', 'X25519']);
    const result = validateCnf({ jwk }, false);
    expect((result as { jwk: Record<string, unknown> }).jwk.crv).toBe('Ed25519');
    expect(calls.count).toBe(1);
  });

  it('非列挙 own メンバも戻り値に保全する（列挙可能のみの複製では欠落する）', () => {
    // `ownProperty` は列挙可否を問わないため非列挙 own の `x` でも検証は通る。戻り値の複製が
    // 列挙可能のみだと検証を通った `x` が戻り値から消え、「形状を保証してから crypto に渡す」が破れる。
    const jwk: Record<string, unknown> = { kty: 'OKP', crv: 'Ed25519' };
    Object.defineProperty(jwk, 'x', { value: HOLDER_X, enumerable: false, configurable: true });
    const result = validateCnf({ jwk }, false);
    expect((result as { jwk: Record<string, unknown> }).jwk.x).toBe(HOLDER_X);
  });

  it('検証対象外メンバの throwing getter は契約内のコードへ正規化する', () => {
    // `kid` の getter が投げると、写しの生成で VericertsError 以外の例外が素通りしかねない。
    const jwk: Record<string, unknown> = { ...OKP_JWK };
    Object.defineProperty(jwk, 'kid', {
      get() {
        throw new TypeError('boom');
      },
      enumerable: true,
      configurable: true,
    });
    expect(() => validateCnf({ jwk }, false)).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
    expect(() => validateCnf({ jwk }, true)).toThrow(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  it('validateStatus は status_list を 1 度だけ読む（getter が別値を返しても乖離しない）', () => {
    const calls = { count: 0 };
    const status: Record<string, unknown> = {};
    Object.defineProperty(status, 'status_list', {
      get() {
        calls.count += 1;
        return calls.count === 1 ? { ...OWN_STATUS_LIST } : { ...EVIL_STATUS_LIST };
      },
      enumerable: true,
      configurable: true,
    });
    expect(validateStatus(status)).toEqual({ status_list: { ...OWN_STATUS_LIST } });
    expect(calls.count).toBe(1);
  });
});
