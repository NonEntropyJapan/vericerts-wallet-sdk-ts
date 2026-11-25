/**
 * 発行時刻の許容範囲と一回限り使用 VC の `jti` 消費のユニットテスト。
 *
 * 検証内容:
 * - assertWithinReplayWindow: flow ごとの既定ウィンドウ、境界値、未来/過去方向、4014。
 * - vpNonceRetentionMs: 「VP の有効期限 + 30 秒」の保持期間算出。
 * - consumeOneTimeCredential: VC の `exp` まで保持し、2 回目は 4010。VP の寿命では消えない。
 */

import { describe, expect, it } from 'bun:test';
import { CLOCK_SKEW_PROFILE } from '../../../credential/time-claims.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  consumeOneTimeCredential,
  VP_NONCE_RETENTION_GRACE_MS,
  vpNonceRetentionMs,
} from '../one-time-credential.js';
import { assertWithinReplayWindow, REPLAY_WINDOW_SECONDS_BY_FLOW } from '../replay-window.js';
import { createNonceStore } from '../store.js';
import type { NonceContext } from '../types.js';

const NOW_SECONDS = 1_700_000_000;
const JTI = 'f81d4fae-7dec-41d0-a765-00a0c91e6bf6';
const VC_ISSUER = 'did:example:approval-issuer';

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

/** `VericertsError` の code を検査する（非同期版）。 */
async function expectCodeAsync(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code as never);
    return;
  }
  throw new Error('例外が送出されなかった');
}

describe('assertWithinReplayWindow', () => {
  it('flow ごとに既定の時間窓を持つ', () => {
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW.oid4vci).toBe(30);
    // OID4VP の既定値は KB-JWT のクロックスキューと同じ 30 秒。
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW.oid4vp).toBe(30);
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW.siopv2).toBe(60);
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW['wua-pop']).toBe(30);
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW['one-time-credential']).toBe(30);
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW.dpop).toBe(30);
  });

  it('OID4VP の時間窓は KB-JWT のクロックスキュープロファイルと一致する', () => {
    // 二重の窓（replay-window と verifySdJwt のクランプ）が食い違うと緩い方が実効窓になる。
    expect(REPLAY_WINDOW_SECONDS_BY_FLOW.oid4vp).toBe(CLOCK_SKEW_PROFILE.kbJwt);
  });

  it('ウィンドウ内の iat を受理する（境界含む）', () => {
    for (const offset of [0, 30, -30]) {
      expect(() =>
        assertWithinReplayWindow(NOW_SECONDS + offset, 'oid4vp', { nowSeconds: NOW_SECONDS }),
      ).not.toThrow();
    }
  });

  it('過去方向にウィンドウを超えると 4014（時計 -5 分の Wallet）', () => {
    expectCode(
      () => assertWithinReplayWindow(NOW_SECONDS - 300, 'oid4vp', { nowSeconds: NOW_SECONDS }),
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
  });

  it('未来方向にウィンドウを超えると 4014', () => {
    expectCode(
      () => assertWithinReplayWindow(NOW_SECONDS + 61, 'oid4vp', { nowSeconds: NOW_SECONDS }),
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
  });

  it('flow ごとにウィンドウが異なる（oid4vci は ±30s）', () => {
    expect(() =>
      assertWithinReplayWindow(NOW_SECONDS - 30, 'oid4vci', { nowSeconds: NOW_SECONDS }),
    ).not.toThrow();
    expectCode(
      () => assertWithinReplayWindow(NOW_SECONDS - 31, 'oid4vci', { nowSeconds: NOW_SECONDS }),
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
  });

  it('windowSeconds で上書きできる', () => {
    expect(() =>
      assertWithinReplayWindow(NOW_SECONDS - 300, 'oid4vp', {
        nowSeconds: NOW_SECONDS,
        windowSeconds: 600,
      }),
    ).not.toThrow();
  });

  it('iat が数値でなければ 4014', () => {
    for (const bad of [undefined, null, 'x', Number.NaN, Number.POSITIVE_INFINITY]) {
      expectCode(
        () => assertWithinReplayWindow(bad, 'oid4vp', { nowSeconds: NOW_SECONDS }),
        ErrorCodes.CLOCK_SKEW_EXCEEDED,
      );
    }
  });
});

describe('vpNonceRetentionMs（VP の有効期限 + 30 秒）', () => {
  it('VP 期限までの残り時間に 30 秒を加算する', () => {
    const now = 1_700_000_000_000;
    expect(vpNonceRetentionMs(now + 120_000, now)).toBe(120_000 + VP_NONCE_RETENTION_GRACE_MS);
    expect(VP_NONCE_RETENTION_GRACE_MS).toBe(30_000);
  });

  it('VP が既に期限切れでも猶予分は正の値になる', () => {
    const now = 1_700_000_000_000;
    expect(vpNonceRetentionMs(now - 1000, now)).toBe(29_000);
  });
});

describe('consumeOneTimeCredential', () => {
  const nowMs = NOW_SECONDS * 1000;

  it('初回は消費でき、2 回目は 4010 REPLAY_DETECTED', async () => {
    const store = createNonceStore({ backend: 'memory', now: () => nowMs });
    const opts = { jti: JTI, issuer: VC_ISSUER, expSeconds: NOW_SECONDS + 3600, nowMs };
    await expect(consumeOneTimeCredential(store, opts)).resolves.toBeUndefined();
    await expectCodeAsync(() => consumeOneTimeCredential(store, opts), ErrorCodes.REPLAY_DETECTED);
  });

  it('VC の exp まで保持され、VP の寿命（+30s）を超えても再利用できない', async () => {
    // VC は 1 時間有効。VP 相当の保持期間（300s + 30s）を大きく超えた時点でも消費済みのまま。
    let current = nowMs;
    const store = createNonceStore({ backend: 'memory', now: () => current, sweepIntervalMs: 10 });
    const opts = { jti: JTI, issuer: VC_ISSUER, expSeconds: NOW_SECONDS + 3600, nowMs };
    await consumeOneTimeCredential(store, opts);

    current = nowMs + 600_000;
    const ctx: NonceContext = { flow: 'one-time-credential', issuer: VC_ISSUER };
    expect(await store.has(JTI, ctx)).toBe(true);
    await expectCodeAsync(
      () => consumeOneTimeCredential(store, { ...opts, nowMs: current }),
      ErrorCodes.REPLAY_DETECTED,
    );
  });

  it('VC の exp を過ぎると 4011 NONCE_EXPIRED', async () => {
    const store = createNonceStore({ backend: 'memory', now: () => nowMs });
    await expectCodeAsync(
      () =>
        consumeOneTimeCredential(store, {
          jti: JTI,
          issuer: VC_ISSUER,
          expSeconds: NOW_SECONDS - 1,
          nowMs,
        }),
      ErrorCodes.NONCE_EXPIRED,
    );
  });

  it('発行者が異なれば別コンテキストとして扱う', async () => {
    const store = createNonceStore({ backend: 'memory', now: () => nowMs });
    const opts = { jti: JTI, issuer: VC_ISSUER, expSeconds: NOW_SECONDS + 3600, nowMs };
    await consumeOneTimeCredential(store, opts);
    await expect(
      consumeOneTimeCredential(store, { ...opts, issuer: 'did:example:other' }),
    ).resolves.toBeUndefined();
  });

  it('jti の形式が不正なら 4013 NONCE_MALFORMED', async () => {
    const store = createNonceStore({ backend: 'memory', now: () => nowMs });
    await expectCodeAsync(
      () =>
        consumeOneTimeCredential(store, {
          jti: 'not-a-uuid',
          issuer: VC_ISSUER,
          expSeconds: NOW_SECONDS + 3600,
          nowMs,
        }),
      ErrorCodes.NONCE_MALFORMED,
    );
  });
});
