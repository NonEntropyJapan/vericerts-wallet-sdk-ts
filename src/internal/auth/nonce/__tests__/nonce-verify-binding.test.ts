/**
 * `verifySdJwt` の `aud` / `nonce` 定数時間比較の振る舞いテスト。
 *
 * 実測時間は環境依存で安定しないため時間そのものは測らず、`timingSafeEqualString` へ
 * 置き換えたことで判定結果が変わっていないこと（一致で成功・不一致と型不正で 3012）を保証する。
 */

import { describe, expect, it } from 'bun:test';
import {
  AUD,
  IAT,
  ISSUER_JWK,
  issue,
  SESSION_SIGNER,
} from '../../../credential/sdjwt/__tests__/key-binding.fixtures.js';
import { addKeyBinding, verifySdJwt } from '../../../credential/sdjwt/verify.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { timingSafeEqualString } from '../../../timing-safe.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';

/** `VericertsError` の code を検査する。 */
function expectCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code as never);
    return;
  }
  throw new Error('例外が送出されなかった');
}

/** KB-JWT 付きの提示を組み立てる。 */
function present(nonce = NONCE, audience = AUD): string {
  return addKeyBinding(issue(), SESSION_SIGNER, { nonce, audience, iatSeconds: IAT });
}

describe('verifySdJwt の aud / nonce 照合', () => {
  it('一致すれば検証に成功する', () => {
    const verified = verifySdJwt(present(), {
      issuerKey: ISSUER_JWK,
      audience: AUD,
      nonce: NONCE,
      nowSeconds: IAT,
    });
    expect(verified.keyBindingVerified).toBe(true);
  });

  it('nonce が 1 文字違うだけでも 3012 で拒否する', () => {
    expectCode(
      () =>
        verifySdJwt(present(), {
          issuerKey: ISSUER_JWK,
          nonce: 'AQIDBAUGBwgJCgsMDQ4PEB',
          nowSeconds: IAT,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('nonce の長さが違っても 3012 で拒否する', () => {
    expectCode(
      () => verifySdJwt(present(), { issuerKey: ISSUER_JWK, nonce: `${NONCE}X`, nowSeconds: IAT }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('aud が不一致なら 3012 で拒否する', () => {
    expectCode(
      () =>
        verifySdJwt(present(), {
          issuerKey: ISSUER_JWK,
          audience: 'https://evil.example/client',
          nowSeconds: IAT,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('比較は timingSafeEqualString と同じ判定になる', () => {
    expect(timingSafeEqualString(NONCE, NONCE)).toBe(true);
    expect(timingSafeEqualString(NONCE, `${NONCE}X`)).toBe(false);
  });
});
