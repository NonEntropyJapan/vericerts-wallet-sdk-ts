/**
 * `verifySdJwtWithReplayGuard` における `audience` 併用時の挙動。
 *
 * 回帰対象: ラッパが呼び出し側の `audience` を黙って捨てていたため、`nonceStore` /
 * `nonceContext` を足した瞬間に `audience` の検査対象が `nonceContext` の束縛値へ
 * すり替わっていた（silent behavior change）。両方を指定した場合は一致を必須とし、不一致なら 4012 を返す。
 */

import { describe, expect, it } from 'bun:test';
import {
  AUD,
  IAT,
  ISSUER_JWK,
  issue,
  SESSION_JWK,
  SESSION_SIGNER,
} from '../../../credential/sdjwt/__tests__/key-binding.fixtures.js';
import { addKeyBinding, verifySdJwt } from '../../../credential/sdjwt/verify.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { verifySdJwtWithReplayGuard } from '../guard.js';
import { createNonceStore } from '../store.js';
import type { NonceContext, NonceStore } from '../types.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };
const OTHER_AUD = 'https://other-rp.example/client';

/** `VericertsError` の code を検査する（非同期版）。 */
async function expectCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code as never);
    return;
  }
  throw new Error('例外が送出されなかった');
}

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => IAT * 1000 });
}

/** KB-JWT 付きの提示を組み立てる。 */
function present(): string {
  return addKeyBinding(issue(), SESSION_SIGNER, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  });
}

/** KB-JWT を「コンパクト JWS として壊れた」文字列へ差し替えた提示。 */
function brokenKeyBinding(): string {
  const bound = present();
  return `${bound.slice(0, bound.lastIndexOf('~') + 1)}not-a-jws`;
}

describe('verifySdJwtWithReplayGuard: audience 併用', () => {
  it('audience が nonceContext の束縛値と一致すれば検証は成功する', async () => {
    const store = makeStore();
    const verified = await verifySdJwtWithReplayGuard(present(), {
      issuerKey: ISSUER_JWK,
      audience: AUD,
      nonce: NONCE,
      nonceContext: CTX,
      nonceStore: store,
      nowSeconds: IAT,
    });

    expect(verified.keyBindingVerified).toBe(true);
    expect(await store.has(NONCE, CTX)).toBe(true);
  });

  it('audience が束縛値と不一致なら 4012（黙って捨てない）', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present(), {
          issuerKey: ISSUER_JWK,
          audience: OTHER_AUD,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT,
        }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
  });

  it('audience 不整合で拒否された提示は nonce を消費しない', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present(), {
          issuerKey: ISSUER_JWK,
          audience: OTHER_AUD,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT,
        }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('audience 未指定なら従来どおり束縛値だけで照合する', async () => {
    const store = makeStore();
    await expect(
      verifySdJwtWithReplayGuard(present(), {
        issuerKey: ISSUER_JWK,
        nonce: NONCE,
        nonceContext: CTX,
        nonceStore: store,
        nowSeconds: IAT,
      }),
    ).resolves.toBeDefined();
  });

  it('ラッパ無しで弾かれる audience は、nonceStore 追加後も弾かれる（挙動が反転しない）', async () => {
    // ラッパを経由しない verifySdJwt は audience 不一致を 3012 として弾く。
    expect(() =>
      verifySdJwt(present(), {
        issuerKey: ISSUER_JWK,
        audience: OTHER_AUD,
        nonce: NONCE,
        nowSeconds: IAT,
        requireKeyBinding: true,
      }),
    ).toThrow(VericertsError);

    // nonceStore / nonceContext を足しても「通ってしまう」ことはなく 4012 になる。
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present(), {
          issuerKey: ISSUER_JWK,
          audience: OTHER_AUD,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: makeStore(),
          nowSeconds: IAT,
        }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
  });
});

describe('verifySdJwtWithReplayGuard: 束縛値の欠落', () => {
  it('束縛値が空文字の nonceContext は 4012（委譲先の 3012 に流さない）', async () => {
    // `verifySdJwt` は `requireKeyBinding: true` に非空の audience を要求する。空の
    // 束縛値はそもそも Verifier を識別できないため、委譲前に本ラッパの失敗面 4012 で閉じる。
    const emptyCtx: NonceContext = { flow: 'oid4vp', clientId: '' };
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present(), {
          issuerKey: ISSUER_JWK,
          nonce: NONCE,
          nonceContext: emptyCtx,
          nonceStore: makeStore(),
          nowSeconds: IAT,
        }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
  });

  it('KB-JWT が構造不正なら 3012（委譲先と同じコードへ正規化する）', async () => {
    // aud 照合を委譲前へ移したため、KB-JWT のデコードも本ラッパが行う。素の
    // デコード例外（2001）を漏らさず、従来どおり KB 経路の失敗面 3012 に揃うことを固定する。
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(brokenKeyBinding(), {
          issuerKey: ISSUER_JWK,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: makeStore(),
          nowSeconds: IAT,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });
});

describe('verifySdJwtWithReplayGuard: 複合失敗時の優先順位', () => {
  /**
   * `aud` 照合を暗号検証より前へ移したため、**両方が失敗する**提示ではバインディング / KB 構造側の
   * コードが先に出る（旧順序なら委譲先の暗号検証が先に走り、いずれも `3010` になっていた）。
   * 単独失敗時のコードは不変で、変わるのはこの優先順位だけ。
   *
   * `SESSION_JWK` は secp256k1 なので、ES256 で署名された Issuer JWT の検証は必ず不成立になる
   * （＝ Issuer 署名不正を作るための誤鍵）。
   */
  const otherAudienceCtx: NonceContext = { flow: 'oid4vp', clientId: OTHER_AUD };

  it('Issuer 署名不正 ＋ aud 不一致は 4012（旧順序では 3010 だった）', async () => {
    // 誤鍵で Issuer 署名は不成立、かつ束縛値 OTHER_AUD に対して提示の aud（AUD）は不一致。
    // 旧順序（暗号検証 → バインディング）ならここは 3010 になる。
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present(), {
          issuerKey: SESSION_JWK,
          nonce: NONCE,
          nonceContext: otherAudienceCtx,
          nonceStore: makeStore(),
          nowSeconds: IAT,
        }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
  });

  it('Issuer 署名不正 ＋ KB-JWT 構造不正は 3012（旧順序では 3010 だった）', async () => {
    // 誤鍵で Issuer 署名は不成立、かつ KB-JWT はコンパクト JWS として壊れている。
    // 旧順序なら委譲先の Issuer 署名検証が先に落ちて 3010 になる。
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(brokenKeyBinding(), {
          issuerKey: SESSION_JWK,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: makeStore(),
          nowSeconds: IAT,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('aud が一致していれば Issuer 署名不正は従来どおり 3010（単独失敗時のコードは不変）', async () => {
    // バインディングを通過した後は委譲先の暗号検証が失敗面を決める。
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present(), {
          issuerKey: SESSION_JWK,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: makeStore(),
          nowSeconds: IAT,
        }),
      ErrorCodes.SIG_INVALID,
    );
  });
});
