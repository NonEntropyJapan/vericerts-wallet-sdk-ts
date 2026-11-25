/**
 * DPoP の JWK メンバ読み取りの `Object.prototype` 汚染耐性テスト。
 *
 * `toDpopPublicKeyJwk` の `d` 不在チェックと `kty` / `crv` / `x` / `y` の読み取りがプロトタイプ鎖を
 * 辿ると、
 *
 * - `Object.prototype.d` 汚染下で **`d` を持たない正当な JWK が誤って拒否**される（DoS）、
 * - `Object.prototype.kty` / `crv` / `x` / `y` 汚染下で **そのメンバを欠く不正な JWK が継承値で
 *   補われて受理**される、
 *
 * という非対称な壊れ方をする。`computeJwkThumbprint` も `toDpopPublicKeyJwk` 経由で同じ影響を受ける。
 *
 * なお `verifyDpopProof` 経路の proof header は `jws.ts` が `parseJsonWithoutPrototype` で読むため
 * 既に null プロトタイプであり、この経路だけでは欠陥が再現しない。`toDpopPublicKeyJwk` は
 * `createDpopProof`（`signer.publicKeyJwk`）や呼び出し側が用意した JWK も受け取るため、テストは
 * 関数単体で汚染耐性を検証し、`verifyDpopProof` 側は汚染下の非退行のみを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { createPrivateKeySigner } from '../../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { createDpopProof } from '../../dpop.js';
import { computeJwkThumbprint, toDpopPublicKeyJwk } from '../../dpop-common.js';
import { verifyDpopProof } from '../../dpop-verify.js';

const KEY = new Uint8Array(32).fill(7);
const SIGNER = createPrivateKeySigner(KEY, 'ES256');
const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';
const NOW = 1_767_225_600;

/** 実鍵から得た正当な EC 公開鍵 JWK（`kty` / `crv` / `x` / `y` を own で持つ）。 */
const VALID_JWK = SIGNER.publicKeyJwk as unknown as Readonly<Record<string, unknown>>;

const MALFORMED = new VericertsError(ErrorCodes.DPOP_PROOF_MALFORMED);

/** `VALID_JWK` から指定メンバを取り除いた JWK を作る（残りは own プロパティ）。 */
function jwkWithout(omitted: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const key of ['kty', 'crv', 'x', 'y']) {
    if (key !== omitted) {
      result[key] = VALID_JWK[key];
    }
  }
  return result;
}

describe('toDpopPublicKeyJwk の JWK メンバ汚染耐性', () => {
  it('継承した d では正当な JWK を拒否しない', () => {
    // 鎖読みだと `jwk.d` が汚染値を拾い、`d` を持たない正当な JWK が 4080 で落ちる（DoS）。
    const normalized = withPollutedPrototype({ d: 'attacker-private-key' }, () =>
      toDpopPublicKeyJwk(VALID_JWK, 'ES256'),
    );
    expect(normalized).toEqual({
      kty: 'EC',
      crv: 'P-256',
      x: VALID_JWK.x as string,
      y: VALID_JWK.y as string,
    });
  });

  it('自身のプロパティとして d を持つ JWK は従来どおり拒否する', () => {
    expect(() => toDpopPublicKeyJwk({ ...VALID_JWK, d: 'secret' }, 'ES256')).toThrow(MALFORMED);
  });

  it('継承した kty では kty を欠く JWK を受理しない', () => {
    expect(() =>
      withPollutedPrototype({ kty: 'EC' }, () => toDpopPublicKeyJwk(jwkWithout('kty'), 'ES256')),
    ).toThrow(MALFORMED);
  });

  it('継承した crv では crv を欠く JWK を受理しない', () => {
    expect(() =>
      withPollutedPrototype({ crv: 'P-256' }, () => toDpopPublicKeyJwk(jwkWithout('crv'), 'ES256')),
    ).toThrow(MALFORMED);
  });

  it('継承した x では x を欠く JWK を受理しない', () => {
    expect(() =>
      withPollutedPrototype({ x: VALID_JWK.x }, () => toDpopPublicKeyJwk(jwkWithout('x'), 'ES256')),
    ).toThrow(MALFORMED);
  });

  it('継承した y では y を欠く JWK を受理しない', () => {
    expect(() =>
      withPollutedPrototype({ y: VALID_JWK.y }, () => toDpopPublicKeyJwk(jwkWithout('y'), 'ES256')),
    ).toThrow(MALFORMED);
  });

  it('汚染が無ければ従来どおり必須メンバのみへ正規化する（正常系）', () => {
    const normalized = toDpopPublicKeyJwk({ ...VALID_JWK, kid: 'key-1', use: 'sig' }, 'ES256');
    expect(normalized).toEqual({
      kty: 'EC',
      crv: 'P-256',
      x: VALID_JWK.x as string,
      y: VALID_JWK.y as string,
    });
  });
});

describe('computeJwkThumbprint の JWK メンバ汚染耐性', () => {
  /** 汚染の無い環境での基準サムプリント。 */
  const expected = computeJwkThumbprint(VALID_JWK, 'ES256');

  it('継承した d では正当な JWK のサムプリント計算を拒否しない', () => {
    const jkt = withPollutedPrototype({ d: 'attacker-private-key' }, () =>
      computeJwkThumbprint(VALID_JWK, 'ES256'),
    );
    expect(jkt).toBe(expected);
  });

  it('継承した x ではメンバを欠く JWK のサムプリントを算出しない', () => {
    expect(() =>
      withPollutedPrototype({ x: VALID_JWK.x }, () =>
        computeJwkThumbprint(jwkWithout('x'), 'ES256'),
      ),
    ).toThrow(MALFORMED);
  });

  // RFC 7638 正準 JSON との一致そのものは `dpop.test.ts` が担うため、ここでは重複させない。
  it('余分なメンバがあってもサムプリントは変わらない（正常系）', () => {
    expect(computeJwkThumbprint({ ...VALID_JWK, kid: 'key-1' }, 'ES256')).toBe(expected);
  });
});

describe('verifyDpopProof の d 汚染下での非退行', () => {
  it('d 汚染下でも正当な proof の生成・検証が通る', () => {
    // 生成側の `signer.publicKeyJwk` は通常のオブジェクトなので、鎖読みだと `d` 汚染で
    // **proof の生成そのものが 4080 で落ちる**。検証側は header が null プロトタイプのため
    // 元から影響を受けないが、経路全体が汚染下で通ることを確認する。
    const verified = withPollutedPrototype({ d: 'attacker-private-key' }, () => {
      const proof = createDpopProof(
        { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
        SIGNER,
      );
      return verifyDpopProof(proof, { htm: HTM, htu: HTU, nowSeconds: NOW });
    });
    expect(verified.jti).toBe('3b241101-e2bb-4255-8caf-4136c566a962');
  });
});
