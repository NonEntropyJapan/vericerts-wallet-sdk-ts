/**
 * SD-JWT 検証の own-property 読み取り統一の回帰テスト。
 *
 * `verify.ts` の `assertAlg` / `typ` 読み取りと、`key-binding-verify.ts` の KB-JWT ヘッダ・payload
 * 読み取りがプロトタイプ鎖を辿っていた。`Object.prototype` 汚染下では、**そのヘッダ / クレームを
 * 持たない** SD-JWT / KB-JWT が継承値を「実際に入っていた値」として扱われる。
 *
 * ここで読む対象はいずれも `JSON.parse` 済みの JWS ヘッダ / payload（外部入力の素のオブジェクト）
 * であり、クラスインスタンスにも関数値にもならない。したがって `nonObjectPrototypeProperty` では
 * なく `ownProperty`（own 限定）が正しい（`own-property.ts` の使い分け）。DI 依存を own 限定で
 * 読んではならないという規則の対象外である。
 *
 * 汚染は共有フィクスチャ `internal/__tests__/prototype-pollution.fixtures.ts` の
 * `withPollutedPrototype` で仕込む（非列挙・必ず復元）。
 *
 * 親ディレクトリ `sdjwt/__tests__/` は Linterly のディレクトリ行数上限（2000 行）を既に超過している
 * ため、本ファイルはサブディレクトリに置く。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getP256PublicKey } from '../../../../keymanager/signer.js';
import { createPrivateKeySigner } from '../../../vc/signer.js';
import { computeSdHash } from '../../key-binding.js';
import { createSdJwt } from '../../sdjwt.js';
import { verifySdJwt } from '../../verify.js';

const b64uText = (text: string): string => Buffer.from(text).toString('base64url');

function toJwk(pub: Uint8Array): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_KEY = new Uint8Array(32).fill(7);
const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false));
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

const HOLDER_KEY = new Uint8Array(32).fill(9);
const HOLDER_JWK = toJwk(getP256PublicKey(HOLDER_KEY, false));
const HOLDER_SIGNER = createPrivateKeySigner(HOLDER_KEY, 'ES256');

const VCT = 'https://example.com/credentials/identity';
const NOW = Math.floor(Date.parse('2026-01-01T00:00:00Z') / 1000);
const AUDIENCE = 'https://verifier.example';
const NONCE = 'n-abc';

/** 任意のヘッダを手組みし、実 issuer 鍵で署名した SD-JWT（Disclosure なし）を作る。 */
function issuerJwtWithRawHeader(header: Record<string, unknown>): string {
  const payload = { vct: VCT, iat: NOW, _sd: [], _sd_alg: 'sha-256' };
  const signingInput = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = ISSUER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(sig).toString('base64url')}~`;
}

/** `cnf` 付きの正常な SD-JWT（提示部、KB-JWT なし）を発行する。 */
function issuePresentable(): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    disclosureClaims: [],
    claims: { name: 'Alice' },
    cnf: { jwk: HOLDER_JWK },
    nowSeconds: NOW,
  });
}

/**
 * 任意のヘッダ・payload を持つ KB-JWT を holder 鍵で**正しく署名して**連結する。
 *
 * 署名は常に妥当にするので、`typ` / `alg` / `aud` / `nonce` の読み取り方だけを切り分けられる。
 */
function attachRawKb(
  sdJwt: string,
  header: Record<string, unknown>,
  payloadOverrides: Record<string, unknown>,
): string {
  const payload = { sd_hash: computeSdHash(sdJwt), iat: NOW, ...payloadOverrides };
  const signingInput = `${b64uText(JSON.stringify(header))}.${b64uText(JSON.stringify(payload))}`;
  const sig = HOLDER_SIGNER.sign(new TextEncoder().encode(signingInput));
  return `${sdJwt}${signingInput}.${Buffer.from(sig).toString('base64url')}`;
}

const baseOpts = { issuerKey: ISSUER_JWK, nowSeconds: NOW } as const;

describe('verify.ts: Issuer-signed JWT ヘッダの own 読み取り', () => {
  it('alg を持たないヘッダは Object.prototype.alg の汚染下でも 3010 で閉じる', () => {
    // 汚染値 'none' を拾うと 3011（ALG_NONE）へ分岐してしまう。own 読みなら undefined のまま 3010。
    const sdJwt = issuerJwtWithRawHeader({ typ: 'dc+sd-jwt' });
    const error = withPollutedPrototype({ alg: 'none' }, () => {
      try {
        verifySdJwt(sdJwt, baseOpts);
        return null;
      } catch (e) {
        return e;
      }
    });
    expect(error).toEqual(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('typ 欠落の受理が Object.prototype.typ の汚染で拒否に変わらない', () => {
    // 「typ 欠落は受理する」は verify.ts が文書化した挙動。鎖読みだと汚染値 'JWT' が
    // 受理対象外 typ として判定され、正当な SD-JWT が一律 3002 になる（可用性の欠陥）。
    const sdJwt = issuerJwtWithRawHeader({ alg: 'ES256' });
    const result = withPollutedPrototype({ typ: 'JWT' }, () => verifySdJwt(sdJwt, baseOpts));
    expect(result.vct).toBe(VCT);
  });

  it('汚染が無い通常の検証は退行しない（typ 明示あり / 欠落ともに受理）', () => {
    expect(
      verifySdJwt(issuerJwtWithRawHeader({ alg: 'ES256', typ: 'dc+sd-jwt' }), baseOpts).vct,
    ).toBe(VCT);
    expect(verifySdJwt(issuerJwtWithRawHeader({ alg: 'ES256' }), baseOpts).vct).toBe(VCT);
  });

  it('受理対象外の typ を実際に持つヘッダは従来どおり 3002', () => {
    const sdJwt = issuerJwtWithRawHeader({ alg: 'ES256', typ: 'kb+jwt' });
    expect(() => verifySdJwt(sdJwt, baseOpts)).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});

describe('key-binding-verify.ts: KB-JWT の own 読み取り', () => {
  const kbOpts = {
    ...baseOpts,
    audience: AUDIENCE,
    nonce: NONCE,
    requireKeyBinding: true,
  } as const;

  it('typ を持たない KB-JWT は Object.prototype.typ 汚染下でも 3012（型混同を素通りさせない）', () => {
    const sdJwt = issuePresentable();
    const presented = attachRawKb(sdJwt, { alg: 'ES256' }, { aud: AUDIENCE, nonce: NONCE });
    expect(() =>
      withPollutedPrototype({ typ: 'kb+jwt' }, () => verifySdJwt(presented, kbOpts)),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('alg を持たない KB-JWT は Object.prototype.alg 汚染下でも 3012（署名検証を続行しない）', () => {
    // 署名自体は holder 鍵で妥当に作ってあるため、鎖読みだと汚染 alg で検証が成立して
    // keyBindingVerified: true になる（alg を宣言していない KB-JWT の受理 = fail-open）。
    const sdJwt = issuePresentable();
    const presented = attachRawKb(sdJwt, { typ: 'kb+jwt' }, { aud: AUDIENCE, nonce: NONCE });
    expect(() =>
      withPollutedPrototype({ alg: 'ES256' }, () => verifySdJwt(presented, kbOpts)),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('aud を持たない KB-JWT は Object.prototype.aud 汚染下でも 3012', () => {
    const sdJwt = issuePresentable();
    const presented = attachRawKb(sdJwt, { alg: 'ES256', typ: 'kb+jwt' }, { nonce: NONCE });
    expect(() =>
      withPollutedPrototype({ aud: AUDIENCE }, () => verifySdJwt(presented, kbOpts)),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('nonce を持たない KB-JWT は Object.prototype.nonce 汚染下でも 3012', () => {
    const sdJwt = issuePresentable();
    const presented = attachRawKb(sdJwt, { alg: 'ES256', typ: 'kb+jwt' }, { aud: AUDIENCE });
    expect(() =>
      withPollutedPrototype({ nonce: NONCE }, () => verifySdJwt(presented, kbOpts)),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('クレームを明示的に持つ正常な KB-JWT は退行しない（汚染なし / 汚染下とも成功）', () => {
    const sdJwt = issuePresentable();
    const presented = attachRawKb(
      sdJwt,
      { alg: 'ES256', typ: 'kb+jwt' },
      { aud: AUDIENCE, nonce: NONCE },
    );
    expect(verifySdJwt(presented, kbOpts).keyBindingVerified).toBe(true);
    // 汚染されていても own プロパティが shadow するため判定は変わらない。
    const underPollution = withPollutedPrototype({ aud: 'https://evil.example' }, () =>
      verifySdJwt(presented, kbOpts),
    );
    expect(underPollution.keyBindingVerified).toBe(true);
  });
});
