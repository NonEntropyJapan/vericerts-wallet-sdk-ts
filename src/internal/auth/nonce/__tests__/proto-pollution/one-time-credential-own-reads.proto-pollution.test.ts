/**
 * `consumeOneTimeCredential` の `opts.nowMs` を own 限定読み取りへ揃えたことの回帰テスト。
 *
 * 同ディレクトリの `replay-window.ts` / `guard.ts` / `vp-guard.ts` は「テスト注入用の現在時刻」を
 * すべて own 限定で読むのに対し、`consumeOneTimeCredential` だけがプロトタイプ鎖で読んでいた。
 * `Object.prototype.nowMs` が汚染されると、`nowMs` を**省略した**正当な呼び出しが汚染値を
 * 「現在時刻」として採用し、一回限り使用 VC（Human Approval VC 等）の失効判定が両方向に壊れる。
 *
 * - 小さい汚染値（例 `0`）: 保持期間が巨大な正の値になり、**失効済み VC が消費記録に乗る**（fail-open）。
 * - 大きい汚染値（例 `Number.MAX_SAFE_INTEGER`）: 有効な VC が常に 4011 になり可用性が壊れる。
 *
 * 汚染と無関係に通るテストは無価値なので、検証はすべて「`nowMs` を省略した入力」で行う。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import {
  type ConsumeOneTimeCredentialOptions,
  consumeOneTimeCredential,
} from '../../one-time-credential.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';

const JTI = 'f81d4fae-7dec-41d0-a765-00a0c91e6bf6';
const VC_ISSUER = 'did:example:approval-issuer';
const CTX: NonceContext = { flow: 'one-time-credential', issuer: VC_ISSUER };

/**
 * ストアの基準時刻（UNIX ms）。
 *
 * `nowMs` を省略した経路は実時計（`Date.now()`）で判定されるため、ストア側の固定時刻も
 * 実時計に揃えておかないと TTL 判定だけが別の時間軸で動いてしまう。
 */
const STORE_NOW_MS = Date.now();
const NOW_SECONDS = Math.floor(STORE_NOW_MS / 1000);

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => STORE_NOW_MS });
}

/** `nowMs` を持たないオプション（実時計で判定される正当な呼び出し）。 */
function optsWithoutNowMs(expSeconds: number): ConsumeOneTimeCredentialOptions {
  return { jti: JTI, issuer: VC_ISSUER, expSeconds };
}

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

describe('consumeOneTimeCredential: opts.nowMs の own 限定読み取り', () => {
  it('継承した nowMs: 0 で失効済み VC の消費が通らない（データ汚染 / fail-open）', async () => {
    // 鎖読みだと `now` が 0 になり `retentionMs` が巨大な正の値に化けるため、
    // 1 時間前に失効した VC が 4011 を免れて消費記録に乗る。
    const store = makeStore();
    await withPollutedPrototypeAsync({ nowMs: 0 }, async () => {
      await expectCode(
        () => consumeOneTimeCredential(store, optsWithoutNowMs(NOW_SECONDS - 3600)),
        ErrorCodes.NONCE_EXPIRED,
      );
    });
    // 失効済み VC の `jti` が消費記録に残っていないこと。
    expect(await store.has(JTI, CTX)).toBe(false);
  });

  it('継承した nowMs: 0 を getter で仕込んでも失効判定は変わらない（アクセサ汚染）', async () => {
    const store = makeStore();
    await withPollutedPrototypeAccessorAsync({ nowMs: () => 0 }, async () => {
      await expectCode(
        () => consumeOneTimeCredential(store, optsWithoutNowMs(NOW_SECONDS - 3600)),
        ErrorCodes.NONCE_EXPIRED,
      );
    });
    expect(await store.has(JTI, CTX)).toBe(false);
  });

  it('継承した nowMs: MAX_SAFE_INTEGER は有効な VC を失効扱いにしない（可用性毀損）', async () => {
    // 鎖読みだと `now` が巨大になり `retentionMs` が負に化けるため、1 時間有効な VC が
    // 常に 4011 で拒否され、Human Approval が一切通らなくなる。
    const store = makeStore();
    await withPollutedPrototypeAsync({ nowMs: Number.MAX_SAFE_INTEGER }, async () => {
      await expect(
        consumeOneTimeCredential(store, optsWithoutNowMs(NOW_SECONDS + 3600)),
      ).resolves.toBeUndefined();
    });
    expect(await store.has(JTI, CTX)).toBe(true);
  });

  it('継承した nowMs: MAX_SAFE_INTEGER を getter で仕込んでも受理される（アクセサ汚染）', async () => {
    const store = makeStore();
    await withPollutedPrototypeAccessorAsync({ nowMs: () => Number.MAX_SAFE_INTEGER }, async () => {
      await expect(
        consumeOneTimeCredential(store, optsWithoutNowMs(NOW_SECONDS + 3600)),
      ).resolves.toBeUndefined();
    });
    expect(await store.has(JTI, CTX)).toBe(true);
  });

  it('明示的に渡した nowMs は汚染下でも従来どおり効く（正常系）', async () => {
    // own の `nowMs` を持つ呼び出しは実時計ではなく指定値で判定される（own 化しすぎの回帰検出）。
    // `expSeconds` は実時計では失効済みだが、指定した `nowMs` から見ればまだ有効。
    const expSeconds = NOW_SECONDS - 3600;
    const store = makeStore();
    await withPollutedPrototypeAsync({ nowMs: 0 }, async () => {
      await expect(
        consumeOneTimeCredential(store, {
          jti: JTI,
          issuer: VC_ISSUER,
          expSeconds,
          nowMs: (expSeconds - 60) * 1000,
        }),
      ).resolves.toBeUndefined();
    });
    expect(await store.has(JTI, CTX)).toBe(true);
  });
});
