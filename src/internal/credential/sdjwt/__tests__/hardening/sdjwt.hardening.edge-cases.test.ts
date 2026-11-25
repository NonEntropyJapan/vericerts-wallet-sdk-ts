/**
 * SD-JWT KB-JWT の未来 iat 拒否と、構造不正な KB-JWT のエラーコード正規化の
 * 回帰テスト（実鍵・モック禁止）。基本のハードニングケースは `sdjwt.hardening.test.ts` を参照
 * （1 ファイル 300 行の Linterly 上限のため分離）。共有の鍵・定数・発行ヘルパは
 * `shared.ts` に集約する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { selectDisclosures } from '../../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../../verify.js';
import { HOLDER_SIGNER, ISSUER_JWK, issue } from './shared.js';

describe('SD-JWT KB-JWT の未来 iat 拒否', () => {
  const NONCE = 'n';
  const AUD = 'https://verifier.example';
  const IAT = 1_000_000;

  /** KB-JWT を付与した提示部を作る（iat は数値固定）。 */
  function boundWithIat(iat: number): string {
    return addKeyBinding(selectDisclosures(issue(), ['name']), HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: iat,
    });
  }

  /**
   * 任意の iat 値（非数値含む）を持つ KB-JWT を実鍵で手組みして提示部に連結する。
   * `addKeyBinding` は iat を数値に固定するため、型不正 iat の検証用に base64url で手組みする。
   */
  function boundWithRawIat(presented: string, iat: unknown): string {
    const b64u = (t: string): string => Buffer.from(t).toString('base64url');
    // sd_hash は KB-JWT を除いた提示部（末尾 `~` まで）の SHA-256（base64url）。
    // addKeyBinding と同一計算のため、一度正規の KB を付けて sd_hash を取り出す。
    const sample = addKeyBinding(presented, HOLDER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    const sampleKb = sample.slice(sample.lastIndexOf('~') + 1);
    const samplePayload = JSON.parse(
      Buffer.from(sampleKb.split('.')[1] ?? '', 'base64url').toString(),
    );
    const header = b64u(JSON.stringify({ alg: 'ES256K', typ: 'kb+jwt' }));
    const payload = b64u(
      JSON.stringify({ nonce: NONCE, aud: AUD, iat, sd_hash: samplePayload.sd_hash }),
    );
    const signingInput = `${header}.${payload}`;
    const sig = HOLDER_SIGNER.sign(new TextEncoder().encode(signingInput));
    const kbJwt = `${signingInput}.${Buffer.from(sig).toString('base64url')}`;
    return `${presented}${kbJwt}`;
  }

  it('未来 iat（skew 超過）は CLOCK_SKEW_EXCEEDED（4014）', () => {
    // KB-JWT のスキュー上限は 30s。+120s は超過し、鮮度（3012）ではなく 4014 になる。
    const bound = boundWithIat(IAT + 120);
    expect(() =>
      verifySdJwt(bound, {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        maxAgeSeconds: 300,
        nowSeconds: IAT,
      }),
    ).toThrow(new VericertsError(ErrorCodes.CLOCK_SKEW_EXCEEDED));
  });

  it('skew 内の僅かな未来 iat（now+30, window 30）は検証成功する', () => {
    const bound = boundWithIat(IAT + 30);
    const result = verifySdJwt(bound, {
      issuerKey: ISSUER_JWK,
      audience: AUD,
      nonce: NONCE,
      maxAgeSeconds: 300,
      nowSeconds: IAT,
    });
    expect(result.keyBindingVerified).toBe(true);
  });

  it('過去すぎる iat（maxAgeSeconds 超過）は HOLDER_BIND_MISMATCH（3012）', () => {
    const bound = boundWithIat(IAT);
    expect(() =>
      verifySdJwt(bound, {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        maxAgeSeconds: 300,
        nowSeconds: IAT + 600,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('iat が非有限（非数値）は HOLDER_BIND_MISMATCH（3012）', () => {
    const presented = selectDisclosures(issue(), ['name']);
    const bound = boundWithRawIat(presented, 'not-a-number');
    expect(() =>
      verifySdJwt(bound, {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        maxAgeSeconds: 300,
        nowSeconds: IAT,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });

  it('正常な iat（skew 内・maxAge 内）は検証成功する', () => {
    const bound = boundWithIat(IAT);
    const result = verifySdJwt(bound, {
      issuerKey: ISSUER_JWK,
      audience: AUD,
      nonce: NONCE,
      maxAgeSeconds: 300,
      nowSeconds: IAT + 100,
    });
    expect(result.keyBindingVerified).toBe(true);
  });
});

describe('構造不正な KB-JWT のエラーコード正規化', () => {
  const [NONCE, AUD, IAT] = ['n', 'https://verifier.example', 1_000_000] as const;

  /** 提示部の KB-JWT を任意の文字列へ差し替える。 */
  function withRawKeyBinding(raw: string): string {
    const opts = { nonce: NONCE, audience: AUD, iatSeconds: IAT };
    const bound = addKeyBinding(selectDisclosures(issue(), ['name']), HOLDER_SIGNER, opts);
    return `${bound.slice(0, bound.lastIndexOf('~') + 1)}${raw}`;
  }

  // 修正前はここで `decodeCompactJws` の INVALID_DID（2001）が verifySdJwt の外へ漏れていた。
  // KB-JWT 経路の失敗面は 3012 で定義されているため、そちらへ正規化する。
  it.each([
    ['セグメントが少ない', 'bad.jwt'],
    ['セグメントが多い', 'not.a.valid.jwt'],
    ['base64url として不正', 'a!b.c!d.e!f'],
    ['ヘッダが JSON でない', 'bm90LWpzb24.e30.c2ln'],
  ])('構造不正な KB-JWT（%s）は HOLDER_BIND_MISMATCH（3012）へ正規化される', (_label, raw) => {
    expect(() =>
      verifySdJwt(withRawKeyBinding(raw), {
        issuerKey: ISSUER_JWK,
        audience: AUD,
        nonce: NONCE,
        requireKeyBinding: true,
        nowSeconds: IAT,
      }),
    ).toThrow(new VericertsError(ErrorCodes.HOLDER_BIND_MISMATCH));
  });
});
