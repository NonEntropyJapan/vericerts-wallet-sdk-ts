/**
 * JWT-VP 検証経路への replay 検知接続（`verifyPresentationWithReplayGuard`）の結合テスト。
 *
 * 実鍵で JWT-VP を署名し、実際に検証する（モックは使わない）。
 *
 * 検証内容:
 * - 正常系: 検証成功と nonce の消費記録。
 * - 同一 nonce の 2 回目の提示で 4010 REPLAY_DETECTED。
 * - 発行済み nonce の TTL 超過で 4011 NONCE_EXPIRED。
 * - payload の `aud` / 呼び出し側 `expectedAudience` が束縛値と不一致で 4012。
 * - `iat` が replay-window 外で 4014。
 * - 署名不正な提示では nonce を消費しない（正規 nonce を焼き潰す DoS の防止）。
 * - nonce 不一致は SD-JWT 経路と同じく 3012。
 */

import { describe, expect, it } from 'bun:test';
import {
  FIXTURES,
  sampleVp,
  signerFor,
} from '../../../credential/presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../../credential/presentation/issue.js';
import { createPrivateKeySigner } from '../../../credential/vc/signer.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { createNonceStore } from '../store.js';
import type { NonceContext, NonceStore } from '../types.js';
import {
  type PresentationReplayGuardOptions,
  verifyPresentationWithReplayGuard,
} from '../vp-guard.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const OTHER_NONCE = 'BQIDBAUGBwgJCgsMDQ4PEA';
const AUD = 'https://verifier.example/client';
const OTHER_AUD = 'https://evil.example/client';
const IAT = 1_700_000_000;
const CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };
const KEY = { publicKeyJwk: FIXTURES.ES256.jwk } as const;

/** holder 鍵ではない別の P-256 鍵（署名不正な提示の組み立て用）。 */
const FORGED_SIGNER = createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');

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

/** JWT-VP 提示を組み立てる。 */
function present(
  opts: { nonce?: string; audience?: string; iatSeconds?: number; forged?: boolean } = {},
): string {
  return issuePresentation(sampleVp(), opts.forged === true ? FORGED_SIGNER : signerFor('ES256'), {
    audience: opts.audience ?? AUD,
    nonce: opts.nonce ?? NONCE,
    nowSeconds: opts.iatSeconds ?? IAT,
  });
}

/** ガードの基本オプション（`nonceStore` のみ差し替える）。 */
function guardOpts(store: NonceStore) {
  return { key: KEY, nonce: NONCE, nonceContext: CTX, nonceStore: store, nowSeconds: IAT };
}

describe('verifyPresentationWithReplayGuard: 正常系', () => {
  it('JWT-VP を検証し、nonce を消費する', async () => {
    const store = makeStore();
    const verified = await verifyPresentationWithReplayGuard(present(), guardOpts(store));

    expect(verified.payload.iss).toBe('did:example:holder');
    expect(verified.payload.nonce).toBe(NONCE);
    expect(verified.presentation.holder).toBe('did:example:holder');
    expect(await store.has(NONCE, CTX)).toBe(true);
  });
});

describe('verifyPresentationWithReplayGuard: リプレイ検知', () => {
  it('同一 nonce の 2 回目の提示は 4010 REPLAY_DETECTED', async () => {
    const store = makeStore();
    const presented = present();

    await verifyPresentationWithReplayGuard(presented, guardOpts(store));
    await expectCode(
      () => verifyPresentationWithReplayGuard(presented, guardOpts(store)),
      ErrorCodes.REPLAY_DETECTED,
    );
  });

  it('同じ nonce を別の提示に載せ替えても 4010（提示単位ではなく nonce 単位で検知）', async () => {
    const store = makeStore();

    await verifyPresentationWithReplayGuard(present(), guardOpts(store));
    await expectCode(
      () => verifyPresentationWithReplayGuard(present({ iatSeconds: IAT + 1 }), guardOpts(store)),
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
        verifyPresentationWithReplayGuard(present({ iatSeconds: IAT + 5 }), {
          ...guardOpts(store),
          nowSeconds: IAT + 5,
        }),
      ErrorCodes.NONCE_EXPIRED,
    );
  });
});

describe('verifyPresentationWithReplayGuard: バインディング', () => {
  it('payload の aud が client_id と不一致なら 4012（3012 に潰さない）', async () => {
    const store = makeStore();
    await expectCode(
      () => verifyPresentationWithReplayGuard(present({ audience: OTHER_AUD }), guardOpts(store)),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('expectedAudience が束縛値と不一致なら 4012（黙って捨てない）', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifyPresentationWithReplayGuard(present(), {
          ...guardOpts(store),
          expectedAudience: OTHER_AUD,
        }),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('expectedAudience が束縛値と一致すれば検証は成功する', async () => {
    const store = makeStore();
    await expect(
      verifyPresentationWithReplayGuard(present(), {
        ...guardOpts(store),
        expectedAudience: AUD,
      }),
    ).resolves.toBeDefined();
    expect(await store.has(NONCE, CTX)).toBe(true);
  });
});

describe('verifyPresentationWithReplayGuard: replay-window', () => {
  it('未来方向に window を超えた iat は 4014 CLOCK_SKEW_EXCEEDED', async () => {
    const store = makeStore();
    await expectCode(
      () => verifyPresentationWithReplayGuard(present({ iatSeconds: IAT + 300 }), guardOpts(store)),
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('replayWindowSeconds で狭めた window の外なら 4014（ガード側の判定）', async () => {
    // iat は VP のクロックスキュー（既定 30 s）内だが、ガードの window（5 s）の外。
    const store = makeStore();
    await expectCode(
      () =>
        verifyPresentationWithReplayGuard(present({ iatSeconds: IAT + 10 }), {
          ...guardOpts(store),
          replayWindowSeconds: 5,
        }),
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('replayWindowSeconds で許容幅を広げられる', async () => {
    const store = makeStore();
    await expect(
      verifyPresentationWithReplayGuard(present({ iatSeconds: IAT - 300 }), {
        ...guardOpts(store),
        replayWindowSeconds: 600,
      }),
    ).resolves.toBeDefined();
  });
});

describe('verifyPresentationWithReplayGuard: 入力検証と DoS 耐性', () => {
  it('nonce のフォーマットが不正なら 4013（暗号検証より前に弾く）', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifyPresentationWithReplayGuard(present({ nonce: 'short' }), {
          ...guardOpts(store),
          nonce: 'short',
        }),
      ErrorCodes.NONCE_MALFORMED,
    );
  });

  it('VP の署名が不正なら nonce を消費せず、後から正規の提示が通る', async () => {
    const store = makeStore();

    await expectCode(
      () => verifyPresentationWithReplayGuard(present({ forged: true }), guardOpts(store)),
      ErrorCodes.SIG_INVALID,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);

    // 正規の提示は同じ nonce でまだ通る（nonce を焼き潰していない）。
    await expect(
      verifyPresentationWithReplayGuard(present(), guardOpts(store)),
    ).resolves.toBeDefined();
  });

  it('payload の nonce が期待値と異なれば 3012（SD-JWT 経路と同じ挙動）', async () => {
    const store = makeStore();
    await expectCode(
      () =>
        verifyPresentationWithReplayGuard(
          present({ nonce: 'BQIDBAUGBwgJCgsMDQ4PEA' }),
          guardOpts(store),
        ),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('aud を持たない VP は 4012（束縛対象が無い提示を受理しない）', async () => {
    const store = makeStore();
    const unbound = issuePresentation(sampleVp(), signerFor('ES256'), {
      nonce: NONCE,
      nowSeconds: IAT,
    });
    await expectCode(
      () => verifyPresentationWithReplayGuard(unbound, guardOpts(store)),
      ErrorCodes.NONCE_BINDING_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
  });
});

describe('verifyPresentationWithReplayGuard: オプションの型契約', () => {
  it('expectedNonce はラッパが制御するため指定できない（黙って捨てられない）', () => {
    const options: PresentationReplayGuardOptions = {
      ...guardOpts(makeStore()),
      // @ts-expect-error expectedNonce はラッパが制御するため指定不可
      expectedNonce: OTHER_NONCE,
    };
    expect(options.nonce).toBe(NONCE);
  });

  it('allowUnbound はラッパが制御するため指定できない', () => {
    const options: PresentationReplayGuardOptions = {
      ...guardOpts(makeStore()),
      // @ts-expect-error allowUnbound はラッパが制御するため指定不可
      allowUnbound: false,
    };
    expect(options.nonce).toBe(NONCE);
  });

  it('opts.nonce が唯一の nonce 入力（型を迂回して混入させても照合は覆らない）', async () => {
    const store = makeStore();
    const smuggled = {
      ...guardOpts(store),
      expectedNonce: OTHER_NONCE,
      allowUnbound: true,
    } as PresentationReplayGuardOptions;

    // VP は OTHER_NONCE で束縛されているが、照合は opts.nonce（NONCE）で行われるため 3012。
    await expectCode(
      () => verifyPresentationWithReplayGuard(present({ nonce: OTHER_NONCE }), smuggled),
      ErrorCodes.HOLDER_BIND_MISMATCH,
    );
    expect(await store.has(NONCE, CTX)).toBe(false);
    expect(await store.has(OTHER_NONCE, CTX)).toBe(false);
  });
});
