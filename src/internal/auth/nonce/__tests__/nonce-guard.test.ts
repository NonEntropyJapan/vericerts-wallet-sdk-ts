/**
 * KB-JWT 検証経路への replay 検知接続（`verifySdJwtWithReplayGuard`）の結合テスト。
 *
 * 実鍵で SD-JWT VC を発行し、実際に KB-JWT を付けて提示する（モックは使わない）。
 *
 * 検証内容:
 * - 正常系: 検証成功と nonce の消費記録。
 * - 同一提示の 2 回目で 4010 REPLAY_DETECTED。
 * - KB-JWT の `aud` が `client_id` と不一致で 4012。
 * - `iat` が replay-window 外で 4014。
 * - nonce のフォーマット不正で 4013、KB-JWT 欠落で 3012。
 * - 署名不正な提示では nonce を消費しない（正規 nonce を焼き潰す DoS の防止）。
 */

import { describe, expect, it } from 'bun:test';
import {
  AUD,
  IAT,
  ISSUER_JWK,
  issue,
  OTHER_SIGNER,
  SESSION_SIGNER,
} from '../../../credential/sdjwt/__tests__/key-binding.fixtures.js';
import { addKeyBinding } from '../../../credential/sdjwt/verify.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { verifySdJwtWithReplayGuard } from '../guard.js';
import { createNonceStore } from '../store.js';
import type { NonceContext, NonceStore } from '../types.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };

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
function makeStore(nowSeconds = IAT): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => nowSeconds * 1000 });
}

/** KB-JWT 付きの提示を組み立てる。 */
function present(opts: { nonce?: string; audience?: string; iatSeconds?: number } = {}): string {
  return addKeyBinding(issue(), SESSION_SIGNER, {
    nonce: opts.nonce ?? NONCE,
    audience: opts.audience ?? AUD,
    iatSeconds: opts.iatSeconds ?? IAT,
  });
}

describe('verifySdJwtWithReplayGuard: 正常系', () => {
  it('KB-JWT 付き提示を検証し、nonce を消費する', async () => {
    const store = makeStore();
    const verified = await verifySdJwtWithReplayGuard(present(), {
      issuerKey: ISSUER_JWK,
      nonce: NONCE,
      nonceContext: CTX,
      nonceStore: store,
      nowSeconds: IAT,
    });

    expect(verified.keyBindingVerified).toBe(true);
    expect(verified.claims.name).toBe('Alice');
    expect(await store.has(NONCE, CTX)).toBe(true);
  });
});

describe('verifySdJwtWithReplayGuard: リプレイ検知', () => {
  it('同一 nonce の 2 回目の提示は 4010 REPLAY_DETECTED', async () => {
    const store = makeStore();
    const presented = present();
    const opts = {
      issuerKey: ISSUER_JWK,
      nonce: NONCE,
      nonceContext: CTX,
      nonceStore: store,
      nowSeconds: IAT,
    };

    await verifySdJwtWithReplayGuard(presented, opts);
    await expectCode(() => verifySdJwtWithReplayGuard(presented, opts), ErrorCodes.REPLAY_DETECTED);
  });

  it('同じ nonce を別の提示に載せ替えても 4010（提示単位ではなく nonce 単位で検知）', async () => {
    const store = makeStore();
    const opts = {
      issuerKey: ISSUER_JWK,
      nonce: NONCE,
      nonceContext: CTX,
      nonceStore: store,
      nowSeconds: IAT,
    };

    await verifySdJwtWithReplayGuard(present(), opts);
    await expectCode(
      () => verifySdJwtWithReplayGuard(present({ iatSeconds: IAT + 1 }), opts),
      ErrorCodes.REPLAY_DETECTED,
    );
  });

  it('発行済み nonce が TTL 超過していれば 4011 NONCE_EXPIRED', async () => {
    let currentMs = IAT * 1000;
    const store = createNonceStore({ backend: 'memory', now: () => currentMs });
    await store.put(NONCE, CTX, 1000);
    currentMs = IAT * 1000 + 5000;

    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present({ iatSeconds: IAT + 5 }), {
          issuerKey: ISSUER_JWK,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT + 5,
        }),
      ErrorCodes.NONCE_EXPIRED,
    );
  });
});

describe('verifySdJwtWithReplayGuard: バインディングと時刻', () => {
  it('KB-JWT の aud が client_id と不一致なら 4012', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present({ audience: 'https://evil.example/client' }), {
          issuerKey: ISSUER_JWK,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT,
        }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('iat が replay-window（±60s）外なら 4014', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present({ iatSeconds: IAT - 300 }), {
          issuerKey: ISSUER_JWK,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT,
        }),
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('replayWindowSeconds で許容幅を広げられる', async () => {
    const store = makeStore();
    await expect(
      verifySdJwtWithReplayGuard(present({ iatSeconds: IAT - 300 }), {
        issuerKey: ISSUER_JWK,
        nonce: NONCE,
        nonceContext: CTX,
        nonceStore: store,
        nowSeconds: IAT,
        replayWindowSeconds: 600,
      }),
    ).resolves.toBeDefined();
  });
});

describe('verifySdJwtWithReplayGuard: 入力検証と DoS 耐性', () => {
  it('nonce のフォーマットが不正なら 4013（暗号検証より前に弾く）', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present({ nonce: 'short' }), {
          issuerKey: ISSUER_JWK,
          nonce: 'short',
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT,
        }),
      ErrorCodes.NONCE_MALFORMED,
    );
  });

  it('KB-JWT が無い提示は 3012 HOLDER_BIND_MISMATCH', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(issue(), {
          issuerKey: ISSUER_JWK,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
  });

  it('KB-JWT の署名が不正なら nonce を消費せず、後から正規の提示が通る', async () => {
    const store = makeStore();
    const opts = {
      issuerKey: ISSUER_JWK,
      nonce: NONCE,
      nonceContext: CTX,
      nonceStore: store,
      nowSeconds: IAT,
    };

    // Session 鍵ではない鍵で KB-JWT を署名した提示。
    const forged = addKeyBinding(issue(), OTHER_SIGNER, {
      nonce: NONCE,
      audience: AUD,
      iatSeconds: IAT,
    });
    await expectCode(
      () => verifySdJwtWithReplayGuard(forged, opts),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);

    // 正規の提示は同じ nonce でまだ通る（nonce を焼き潰していない）。
    await expect(verifySdJwtWithReplayGuard(present(), opts)).resolves.toBeDefined();
  });

  it('KB-JWT の nonce が期待値と異なれば 3012（Holder Binding 不一致）', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifySdJwtWithReplayGuard(present({ nonce: 'BQIDBAUGBwgJCgsMDQ4PEA' }), {
          issuerKey: ISSUER_JWK,
          nonce: NONCE,
          nonceContext: CTX,
          nonceStore: store,
          nowSeconds: IAT,
        }),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });
});
