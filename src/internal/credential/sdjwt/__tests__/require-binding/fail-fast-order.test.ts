/**
 * `verifySdJwt` の「期待値の検査は暗号処理より前に fail fast」を
 * 固定する回帰テスト。
 *
 * `require-binding.test.ts` の期待値欠落ケースはすべて**正しい `ISSUER_JWK`** を使っているため
 * Issuer 署名が成立し、`assertBindingExpectationsPresent(opts)` の呼び出しを
 * `assertIssuerSignature` の**後**へ動かしても全件が緑のままだった。つまり期待値検査を先に行う
 * 順序は固定されていなかった（replay guard 側 `nonce-guard-audience.test.ts` は同種の優先順位を
 * 既に固定済みで、sdjwt 層だけが非対称だった）。
 *
 * 順序の証拠は**誤鍵と期待値欠落を組み合わせた複合失敗**でしか取れない。
 *
 * | 入力                              | 結果   | 意味                             |
 * | --------------------------------- | ------ | -------------------------------- |
 * | 誤鍵 ＋ `audience` / `nonce` 欠落 | `3012` | オプション検証が暗号処理より前   |
 * | 誤鍵 ＋ `audience` / `nonce` あり | `3010` | 署名検証で落ちる（対照）         |
 *
 * 順序を入れ替えると 1 行目が `3010` に変わる。**両方の失敗条件が本当に成立していること**が要点で、
 * 誤鍵には `SESSION_JWK`（secp256k1）を使う。提示の Issuer 署名は ES256 なので、この鍵での署名検証は
 * 必ず不成立になる（正しい鍵を渡すと署名が成立してしまい、単独失敗テストと等価になる）。
 *
 * 実鍵のみを使う（モック禁止）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { selectDisclosures } from '../../sdjwt.js';
import { addKeyBinding, verifySdJwt } from '../../verify.js';
import {
  AUD,
  IAT,
  ISSUER_JWK,
  issue,
  NONCE,
  SESSION_JWK,
  SESSION_SIGNER,
} from '../key-binding.fixtures.js';

/** KB-JWT 付きの正当な提示（署名・`sd_hash` はすべて成立する）。 */
function present(): string {
  return addKeyBinding(selectDisclosures(issue(), ['name']), SESSION_SIGNER, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  });
}

/** 送出された `VericertsError` のコードを取り出す（例外が出なければ `undefined`）。 */
function thrownCode(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (error) {
    return error instanceof VericertsError ? error.code : String(error);
  }
}

describe('verifySdJwt — 期待値検査は暗号処理より前に fail fast', () => {
  it('前提: 誤鍵 SESSION_JWK では Issuer 署名が成立しない（期待値ありなら 3010）', () => {
    // 対照ケース。複合失敗の一方（署名不成立）が本当に成立していることの確認でもある。
    expect(
      thrownCode(() =>
        verifySdJwt(present(), {
          issuerKey: SESSION_JWK,
          requireKeyBinding: true,
          audience: AUD,
          nonce: NONCE,
          nowSeconds: IAT,
        }),
      ),
    ).toBe(ErrorCodes.SIG_INVALID);
  });

  it('前提: 正しい鍵で期待値だけ欠けていれば 3012（単独失敗時のコード）', () => {
    expect(
      thrownCode(() =>
        verifySdJwt(present(), {
          issuerKey: ISSUER_JWK,
          requireKeyBinding: true,
          nowSeconds: IAT,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('誤鍵 ＋ audience / nonce の双方が欠落なら 3012（期待値検査が署名検証より前）', () => {
    // 順序を入れ替える（assertBindingExpectationsPresent を assertIssuerSignature の後へ動かす）と
    // ここが 3010 になる。
    expect(
      thrownCode(() =>
        verifySdJwt(present(), {
          issuerKey: SESSION_JWK,
          requireKeyBinding: true,
          nowSeconds: IAT,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('誤鍵 ＋ audience だけ欠落でも 3012', () => {
    expect(
      thrownCode(() =>
        verifySdJwt(present(), {
          issuerKey: SESSION_JWK,
          requireKeyBinding: true,
          nonce: NONCE,
          nowSeconds: IAT,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('誤鍵 ＋ nonce だけ欠落でも 3012', () => {
    expect(
      thrownCode(() =>
        verifySdJwt(present(), {
          issuerKey: SESSION_JWK,
          requireKeyBinding: true,
          audience: AUD,
          nowSeconds: IAT,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });

  it('誤鍵 ＋ 空文字の audience / nonce も 3012（空文字は「未指定」と同じ扱い）', () => {
    expect(
      thrownCode(() =>
        verifySdJwt(present(), {
          issuerKey: SESSION_JWK,
          requireKeyBinding: true,
          audience: '',
          nonce: '',
          nowSeconds: IAT,
        }),
      ),
    ).toBe(ErrorCodes.HOLDER_BIND_MISMATCH);
  });
});
