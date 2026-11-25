/**
 * `validateCnf` の JWK メンバ own 読み取りの回帰テスト（同クラス）。
 *
 * `claims.ts` の `validateCnf` が `cnf.jwk` と JWK の `kty` / `crv` / `x` / `y` をプロトタイプ鎖で
 * 読んでいた（`const { crv, kty } = jwk` の分割代入を含む）。継承付きの `cnf` が渡ると、
 * **そのメンバを持たない** JWK の検証で汚染値が「JWK に実際に入っていた値」として扱われる:
 *
 * - 可用性 / DoS: `Object.prototype.y` 汚染下で、OKP 分岐の `y` 不在チェック（RFC 8037 の OKP 鍵は
 *   `y` を持たない）が継承値を拾い、**正当な Ed25519 の `cnf.jwk` が誤って拒否される**。この面は
 *    `jwk-key.ts` own 化では塞がらない。形状検証を先に行う `validateCnf` で拒否が確定し、
 *   下流の `jwkToOkpPublicKey` へ到達しないためである。
 * - fail-open: `jwk` / `kty` / `crv` / `x` 汚染下で、それらを**欠く JWK が継承値で補われて形状
 *   検証を通過する**。
 *
 * **テストの水準について（重要）**: 現在の `validateCnf` の呼び出し元（`verify.ts` の `verifySdJwt` /
 * `key-binding.ts` の `extractCnfJwk`）は、いずれも Issuer-signed JWT を `vc/jws.ts` の
 * `decodeCompactJws` → `jwt-codec.ts` の `parseJson`（`parseJsonWithoutPrototype`）で読む。この
 * reviver は**入れ子のオブジェクトまで再帰的に `null` プロトタイプ化する**ため、`verifySdJwt` 経由で
 * 届く `cnf` / `cnf.jwk` は `Object.prototype` を継承せず、上記 2 面は**公開 API 経由では現状到達
 * しない**。したがってこの回帰テストは、鎖を断つ責務を負う層である `validateCnf` を**直接
 * 呼んで**検証する（`verifySdJwt` 経由のテストは修正の前後どちらでも通ってしまい、回帰テストとして
 * 機能しない）。own 化そのものは `parse-json.ts` が定める多層防御――「本ヘルパーの導入を理由に
 * 既存の `ownProperty` 呼び出しを削ってはならない」――として必要である。パース境界に依存した
 * 現状の安全性は、下の「パース境界」describe で前提として固定する。
 *
 * 読む対象は JSON 由来の payload（外部入力の素のオブジェクト）であり、クラスインスタンスにも
 * 関数値にもならない。したがって `nonObjectPrototypeProperty` ではなく `ownProperty`（own 限定）
 * が正しい（`own-property.ts` の使い分け）。
 *
 * 汚染は共有フィクスチャ `internal/__tests__/prototype-pollution.fixtures.ts` の
 * `withPollutedPrototype` で仕込む（非列挙・必ず復元）。**汚染値は own 値と必ず食い違わせ**、
 * どちらが読まれたかを戻り値から判別できるようにする（テストがトートロジーになるのを防ぐ）。
 *
 * `validateStatus` の own 読み取りと、own アクセサに対する 1 度読み（TOCTOU）の回帰テストは、
 * ファイル行数上限（300 行）に収めるため `claims-status-accessor.proto-pollution.test.ts` にある。
 *
 * 親ディレクトリ `sdjwt/__tests__/` は Linterly のディレクトリ行数上限（2000 行）を既に超過している
 * ため、サブディレクトリに置く。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { validateCnf } from '../../claims.js';
import { verifySdJwt } from '../../verify.js';

const b64uText = (text: string): string => Buffer.from(text).toString('base64url');
const b64uBytes = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

function toJwk(pub: Uint8Array): PublicKeyJwk {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: b64uBytes(pub.subarray(1, 33)),
    y: b64uBytes(pub.subarray(33, 65)),
  };
}

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const VCT = 'https://example.com/credentials/identity';
const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);

/** Holder の Ed25519 公開鍵座標（32 byte）。`validateCnf` は形状のみ見るため実鍵である必要はない。 */
const HOLDER_X = b64uBytes(new Uint8Array(32).fill(3));
/** own の `y` と必ず食い違う汚染値（どちらが読まれたか戻り値から判別するため）。 */
const POLLUTED_Y = b64uBytes(new Uint8Array(32).fill(200));

/** RFC 8037 準拠の正当な Ed25519 JWK（`y` を持たない）。 */
const OKP_JWK = { kty: 'OKP', crv: 'Ed25519', x: HOLDER_X } as const;

const baseOpts = { issuerKey: ISSUER_JWK, nowSeconds: NOW } as const;

/**
 * 任意の payload を手組みし、実 issuer 鍵で署名した SD-JWT を作る。
 *
 * `createSdJwt` は `cnf` の形を選べないため、汚染が実際に効く payload（`cnf.jwk` がメンバを
 * 欠く形など）を作るには手組みする必要がある。
 */
function issuerJwtWithRawPayload(payload: Record<string, unknown>): string {
  const header = { alg: 'ES256', typ: 'dc+sd-jwt' };
  const signingInput = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = ISSUER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(sig).toString('base64url')}~`;
}

/** 汚染下で `verifySdJwt` を実行し、成功値か送出された例外のどちらかを返す。 */
function verifyUnderPollution(
  props: Readonly<Record<string, unknown>>,
  sdJwt: string,
): { ok: true; cnf: unknown } | { ok: false; error: unknown } {
  return withPollutedPrototype(props, () => {
    try {
      return { ok: true as const, cnf: verifySdJwt(sdJwt, baseOpts).cnf };
    } catch (error) {
      return { ok: false as const, error };
    }
  });
}

/** 汚染下で `validateCnf` を直接実行し、成功値か送出された例外のどちらかを返す。 */
function validateUnderPollution(
  props: Readonly<Record<string, unknown>>,
  value: unknown,
  requireKeyBinding = false,
): { ok: true; cnf: unknown } | { ok: false; error: unknown } {
  return withPollutedPrototype(props, () => {
    try {
      return { ok: true as const, cnf: validateCnf(value, requireKeyBinding) };
    } catch (error) {
      return { ok: false as const, error };
    }
  });
}

describe('claims.ts: validateCnf の `y` own 読み取り（DoS 側）', () => {
  it('y を持たない正当な Ed25519 JWK は Object.prototype.y 汚染下でも受理される', () => {
    // 鎖読みだと OKP 分岐の `jwk.y !== undefined` が継承値 POLLUTED_Y を拾い、RFC 8037 準拠の
    // 正当な Ed25519 JWK が「EC JWK の偽装」として拒否される（可用性の欠陥）。
    const outcome = validateUnderPollution({ y: POLLUTED_Y }, { jwk: { ...OKP_JWK } });
    expect(outcome.ok).toBe(true);
    // 汚染値ではなく own の座標がそのまま返る。
    const jwk = outcome.ok ? (outcome.cnf as { jwk: Record<string, unknown> }).jwk : null;
    expect(jwk === null ? null : jwk.x).toBe(HOLDER_X);
    // 戻り値も鎖を断って返す。元オブジェクトを参照で返すと、own 限定で検証したのに
    // `VerifiedSdJwt.cnf` 経由で継承値（`cnf.jwk.y`）が公開 API から読めてしまう。
    expect(jwk === null ? null : Object.getPrototypeOf(jwk)).toBeNull();
    expect(jwk === null ? 'missing' : jwk.y).toBeUndefined();
  });

  it('KB 必須（3012 経路）でも Object.prototype.y 汚染下の正当な Ed25519 JWK を受理する', () => {
    // `key-binding.ts` の `extractCnfJwk` は requireKeyBinding=true で呼ぶ。汚染下でこちらだけ
    // 3012 で落ちると Holder バインド済みの提示が一切通らなくなる。
    const outcome = validateUnderPollution({ y: POLLUTED_Y }, { jwk: { ...OKP_JWK } }, true);
    expect(outcome.ok).toBe(true);
  });

  it('対照: own の `y` を実際に持つ OKP JWK は汚染が無くても拒否される', () => {
    // 上の受理が「`y` 不在チェックが消えた」からではなく own 限定になったからであることを示す
    // （RFC 8037 違反の EC 偽装を弾くガードは生きている）。
    expect(() => validateCnf({ jwk: { ...OKP_JWK, y: POLLUTED_Y } }, false)).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('対照: 汚染が無ければ正当な Ed25519 cnf.jwk は従来どおり受理される', () => {
    const sdJwt = issuerJwtWithRawPayload({ vct: VCT, iat: NOW, cnf: { jwk: { ...OKP_JWK } } });
    expect((verifySdJwt(sdJwt, baseOpts).cnf as { jwk: { x: string } }).jwk.x).toBe(HOLDER_X);
  });
});

describe('claims.ts: validateCnf の `jwk` / `kty` / `crv` / `x` own 読み取り', () => {
  it('自身のメンバを持たない cnf.jwk は kty/crv/x 汚染下でも形状検証を通過しない', () => {
    // 鎖読みだと `{}` が継承値で「OKP/Ed25519/x 付き」の JWK に見え、形状検証を通過する。
    const outcome = validateUnderPollution(
      { kty: 'OKP', crv: 'Ed25519', x: HOLDER_X },
      { jwk: {} },
    );
    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? null : outcome.error).toEqual(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('`jwk` を持たない cnf は Object.prototype.jwk 汚染下でも形状検証を通過しない', () => {
    // 鎖読みだと `isObject(value.jwk)` が継承した JWK を拾い、Issuer が署名していない鍵が
    // Holder バインド鍵として採用される。
    const outcome = validateUnderPollution({ jwk: { ...OKP_JWK } }, {});
    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? null : outcome.error).toEqual(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('KB 必須なら同じ汚染下の不正 cnf は 3012 で拒否される', () => {
    const outcome = validateUnderPollution(
      { kty: 'OKP', crv: 'Ed25519', x: HOLDER_X },
      { jwk: {} },
      true,
    );
    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? null : outcome.error).toEqual(
      new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH),
    );
  });

  it('own のメンバは汚染を shadow する（汚染値ではなく own の kty / crv で判定する）', () => {
    // own は EC / P-256、汚染は OKP / Ed25519 で食い違わせる。own を読めていれば EC 分岐に入り、
    // `y` を要求して受理される（汚染値を読んでいたら OKP 分岐で `y` 混入として拒否される）。
    const ecJwk = { kty: 'EC', crv: 'P-256', x: HOLDER_X, y: HOLDER_X };
    const outcome = validateUnderPollution({ kty: 'OKP', crv: 'Ed25519' }, { jwk: ecJwk });
    expect(outcome.ok).toBe(true);
    expect(outcome.ok ? (outcome.cnf as { jwk: { crv: string } }).jwk.crv : null).toBe('P-256');
  });

  it('汚染下でも cnf 未設定なら undefined のまま返る（退行しない）', () => {
    const outcome = validateUnderPollution({ jwk: { ...OKP_JWK } }, undefined);
    expect(outcome.ok).toBe(true);
    expect(outcome.ok ? outcome.cnf : 'thrown').toBeUndefined();
  });
});

/**
 * `verifySdJwt` 経由では汚染が `cnf` へ届かないという**前提**を固定する。
 *
 * これは 回帰テストではない（修正の前後どちらでも通る）。`validateCnf` の own 化が
 * 多層防御であること――現状の安全性がパース境界に依存していること――を実行可能な形で記録し、
 * `parseJson` が `parseJsonWithoutPrototype` を使わなくなる等でこの前提が崩れたら気付けるようにする。
 */
describe('claims.ts: cnf のパース境界（前提の固定）', () => {
  it('verifySdJwt が読む cnf.jwk は null プロトタイプで、Object.prototype.y 汚染が届かない', () => {
    const sdJwt = issuerJwtWithRawPayload({ vct: VCT, iat: NOW, cnf: { jwk: { ...OKP_JWK } } });
    const outcome = verifyUnderPollution({ y: POLLUTED_Y }, sdJwt);
    expect(outcome.ok).toBe(true);
    const jwk = outcome.ok ? (outcome.cnf as { jwk: object }).jwk : null;
    expect(jwk === null ? null : Object.getPrototypeOf(jwk)).toBeNull();
  });

  it('verifySdJwt は cnf 未設定の VC を汚染下でも受理する（undefined のまま返る）', () => {
    const sdJwt = issuerJwtWithRawPayload({ vct: VCT, iat: NOW });
    const outcome = verifyUnderPollution({ jwk: { ...OKP_JWK }, y: POLLUTED_Y }, sdJwt);
    expect(outcome.ok).toBe(true);
    expect(outcome.ok ? outcome.cnf : 'thrown').toBeUndefined();
  });
});
