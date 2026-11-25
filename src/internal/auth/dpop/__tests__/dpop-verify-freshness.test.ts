/**
 * DPoP proof の `iat` 鮮度判定と、鮮度オプションの上限キャップ検査の回帰テスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - RFC 9449 §4.3 の手順 11 に従って proof の生成時刻を確認する。SDK の既定では
 *   `iat` が現在時刻の前後 30 秒の範囲を外れると 4082 を返す。
 * - `clockSkewSeconds`（未来側）/ `maxAgeSeconds`（過去側）は既定より厳しい方向へのみ上書きでき、
 *   キャップ（30）超過・非負整数でない値は 4015。
 *   検査は proof のデコード・署名検証より前に fail-fast で行う。
 */

import { describe, expect, it } from 'bun:test';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../errors.js';
import { createDpopProof } from '../dpop.js';
import { verifyDpopProof } from '../dpop-verify.js';
import { DEFAULT_DPOP_MAX_AGE_SECONDS } from '../dpop-verify-options.js';

/** テスト用の固定秘密鍵。鮮度判定・キャップ検査は alg 非依存なので `ES256` のみで足りる。 */
const KEY = new Uint8Array(32).fill(7);

/** 固定現在時刻（エポック秒）。 */
const NOW = 1_767_225_600;

const HTM = 'POST';
const HTU = 'https://api.example.com/mcp';

/** 検証条件の既定値（`htm` / `htu` / `nowSeconds` のみ）。 */
const BASE = { htm: HTM, htu: HTU, nowSeconds: NOW } as const;

/** `verifyDpopProof` が指定コードの VericertsError を投げることを表明する。 */
function expectCode(
  proof: string,
  options: Parameters<typeof verifyDpopProof>[1],
  code: ErrorCode,
): void {
  try {
    verifyDpopProof(proof, options);
    throw new Error('should have thrown');
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    expect((e as VericertsError).code).toBe(code);
  }
}

describe('verifyDpopProof 鮮度（4082）', () => {
  const signer = createPrivateKeySigner(KEY, 'ES256');

  /** 指定した `iat` の proof を生成する。 */
  function proofAt(iat: number): string {
    return createDpopProof(
      { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: iat },
      signer,
    );
  }

  it('maxAgeSeconds を超えて過去なら期限切れ', () => {
    const proof = proofAt(NOW - DEFAULT_DPOP_MAX_AGE_SECONDS - 1);
    expectCode(proof, BASE, ErrorCodes.DPOP_PROOF_EXPIRED);
  });

  it('ちょうど maxAgeSeconds 経過なら成功する（境界値）', () => {
    const proof = proofAt(NOW - DEFAULT_DPOP_MAX_AGE_SECONDS);
    expect(verifyDpopProof(proof, BASE).iat).toBe(NOW - DEFAULT_DPOP_MAX_AGE_SECONDS);
  });

  it('clockSkewSeconds を超えて未来なら期限切れ', () => {
    const proof = proofAt(NOW + 31);
    expectCode(proof, BASE, ErrorCodes.DPOP_PROOF_EXPIRED);
  });

  it('既定より厳しい maxAgeSeconds / clockSkewSeconds が適用される', () => {
    const proof = proofAt(NOW - 20);
    expect(verifyDpopProof(proof, { ...BASE, maxAgeSeconds: 20 }).iat).toBe(NOW - 20);
    expectCode(proof, { ...BASE, maxAgeSeconds: 19 }, ErrorCodes.DPOP_PROOF_EXPIRED);
    const future = proofAt(NOW + 20);
    expect(verifyDpopProof(future, { ...BASE, clockSkewSeconds: 20 }).iat).toBe(NOW + 20);
    expectCode(future, { ...BASE, clockSkewSeconds: 19 }, ErrorCodes.DPOP_PROOF_EXPIRED);
  });
});

/**
 * 鮮度オプションの上限キャップ検査。
 *
 * 「テナントは既定より**厳しい**値のみ設定できる」を
 * `verifyDpopProof` でも強制する。`clockSkewSeconds`（未来側）と `maxAgeSeconds`（過去側）は
 * 既定の ±30 s の許容範囲の両端なので、双方が 30 を上限とする。
 */
describe('verifyDpopProof 鮮度オプションのキャップ（4015）', () => {
  const signer = createPrivateKeySigner(KEY, 'ES256');
  const proof = createDpopProof(
    { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
    signer,
  );

  it('キャップを超える clockSkewSeconds を拒否する', () => {
    expectCode(proof, { ...BASE, clockSkewSeconds: 31 }, ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
    expectCode(proof, { ...BASE, clockSkewSeconds: 3600 }, ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
  });

  it('キャップを超える maxAgeSeconds を拒否する', () => {
    expectCode(proof, { ...BASE, maxAgeSeconds: 31 }, ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
    expectCode(proof, { ...BASE, maxAgeSeconds: 3600 }, ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
  });

  it('非負整数でない値を拒否する', () => {
    expectCode(proof, { ...BASE, clockSkewSeconds: -1 }, ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
    expectCode(proof, { ...BASE, clockSkewSeconds: 1.5 }, ErrorCodes.CLOCK_SKEW_OPTION_INVALID);
    expectCode(
      proof,
      { ...BASE, clockSkewSeconds: Number.NaN },
      ErrorCodes.CLOCK_SKEW_OPTION_INVALID,
    );
    expectCode(
      proof,
      { ...BASE, maxAgeSeconds: Number.POSITIVE_INFINITY },
      ErrorCodes.CLOCK_SKEW_OPTION_INVALID,
    );
  });

  it('キャップちょうど・0・未指定は受理する（境界値）', () => {
    expect(verifyDpopProof(proof, { ...BASE, clockSkewSeconds: 30, maxAgeSeconds: 30 }).iat).toBe(
      NOW,
    );
    expect(verifyDpopProof(proof, { ...BASE, clockSkewSeconds: 0, maxAgeSeconds: 0 }).iat).toBe(
      NOW,
    );
    expect(verifyDpopProof(proof, BASE).iat).toBe(NOW);
  });

  it('署名検証より前に fail-fast で弾く（形式不正な proof でも 4015）', () => {
    expectCode(
      'not-a-jws',
      { ...BASE, clockSkewSeconds: 3600 },
      ErrorCodes.CLOCK_SKEW_OPTION_INVALID,
    );
  });
});

/**
 * 2 つの precondition の評価順。
 *
 * `accessToken` 指定時の `expectedJkt` 必須化（4085）と鮮度オプションのキャップ検査（4015）は
 * どちらも proof のデコード前に評価される。両方が同時に成立する呼び出しでは、sender-constraining
 * が無効化されている方を優先して報告するため 4085 → 4015 の順に評価する。
 */
describe('precondition の評価順（4085 → 4015）', () => {
  const signer = createPrivateKeySigner(KEY, 'ES256');
  const proof = createDpopProof(
    { htm: HTM, htu: HTU, jti: '3b241101-e2bb-4255-8caf-4136c566a962', nowSeconds: NOW },
    signer,
  );

  it('expectedJkt 欠落とキャップ超過が同時成立なら 4085 を返す', () => {
    // 型では表現できない組み合わせを as で作り、ランタイムガードの評価順を確認する。
    const unsafe = {
      ...BASE,
      accessToken: 'access-token-abc123',
      clockSkewSeconds: 3600,
    } as unknown as Parameters<typeof verifyDpopProof>[1];
    expectCode(proof, unsafe, ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
  });

  it('maxAgeSeconds 側のキャップ超過と同時成立でも 4085 を返す', () => {
    const unsafe = {
      ...BASE,
      accessToken: 'access-token-abc123',
      maxAgeSeconds: 3600,
    } as unknown as Parameters<typeof verifyDpopProof>[1];
    expectCode(proof, unsafe, ErrorCodes.DPOP_KEY_BINDING_MISMATCH);
  });
});
