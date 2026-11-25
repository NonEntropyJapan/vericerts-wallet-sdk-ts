/**
 * `NonceStore#checkAndUse` の**単一読み（read-once）**回帰テスト。
 *
 * **修正前の欠陥**: store 層は 1 回の消費で束縛値を 3 回読んでいた。
 *
 * 1. `assertBinding(ctx, opts.binding)` の照合（読み取り 1 回目）
 * 2. `entryKeyOf(nonce, ctx)` の拒否リストキー組み立て（読み取り 2 回目）
 * 3. `NonceCapacityManager#enforceCapacity(ctx, key)` の容量スコープ（読み取り 3 回目）
 *
 * 致命的なのは 2 で、**拒否リストキーが束縛照合を一度も通っていない読み取り値から算出されて
 * いた**。束縛メンバを own の**アクセサ**として持つ `NonceContext`（`context.ts` 冒頭が TOCTOU の
 * 前提として挙げる形）では読み取りごとに別値を返し得るため、照合済みの束縛値とは**別のキー
 * 空間**へ消費記録が書かれる。結果として拒否リストに載らず、同じ nonce をリプレイできる。
 *
 * 本ファイルは store 層だけを直接叩き、暗号処理を挟まずにこの不変条件を固定する
 * （guard 層を通した経路は同ディレクトリの `*-guard.binding-read-once.test.ts` が担う）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';
import { EVIL_BINDING, expectCode, taintedBindingContext } from './binding-read-once.fixtures.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
/** 束縛照合を通る正規の Verifier（消費記録はこのキー空間に載らなければならない）。 */
const VERIFIER = 'https://verifier.example/client';

const PLAIN_CTX: NonceContext = { flow: 'oid4vp', clientId: VERIFIER };
const EVIL_CTX: NonceContext = { flow: 'oid4vp', clientId: EVIL_BINDING };

/**
 * store 層だけを通す汚染コンテキスト。
 *
 * 修正前は読み取り 1 回目が `assertBinding` の照合（正規値なので通る）、2 回目が `entryKeyOf` の
 * キー組み立て（攻撃者の値）だった。したがって 2 回目を汚染すると欠陥が露出する。
 *
 * @returns 汚染コンテキストと束縛メンバの読み取り回数。
 */
function taintedContext(): { readonly ctx: NonceContext; readonly reads: () => number } {
  return taintedBindingContext({
    flow: 'oid4vp',
    member: 'clientId',
    value: VERIFIER,
    taintedRead: 2,
  });
}

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => 1_700_000_000_000 });
}

describe('NonceStore#checkAndUse: 束縛値は 1 度だけ読む', () => {
  it('照合の後に別値を返すコンテキストでも、消費記録は照合済み束縛値のキー空間に載る', async () => {
    const store = makeStore();
    const { ctx, reads } = taintedContext();
    await store.checkAndUse(NONCE, ctx, { binding: VERIFIER });

    // 主アサーション: 消費記録は「照合を通した束縛値」のキー空間にある。
    // 修正前はここが false（＝拒否リストに載らない）だった。
    expect(await store.has(NONCE, PLAIN_CTX)).toBe(true);
    // 攻撃者が選んだキー空間には何も書かれていない。
    expect(await store.has(NONCE, EVIL_CTX)).toBe(false);
    // store 層の読み取りは `resolveBinding` の 1 回だけ（＝汚染した 2 回目には到達しない）。
    // 修正前は照合・キー組み立て・容量スコープで 3 回読んでいた。
    expect(reads()).toBe(1);
  });

  it('汚染コンテキストで消費した nonce は、素のコンテキストの 2 回目の提示で 4010', async () => {
    const store = makeStore();
    await store.checkAndUse(NONCE, taintedContext().ctx, { binding: VERIFIER });

    // 修正前は消費記録が別キー空間にあるため「初見」として受理され、リプレイが通っていた。
    await expectCode(
      () => store.checkAndUse(NONCE, PLAIN_CTX, { binding: VERIFIER }),
      ErrorCodes.REPLAY_DETECTED,
    );
  });

  it('汚染コンテキストを再提示しても 4010（同じ汚染でもキー空間はぶれない）', async () => {
    const store = makeStore();
    await store.checkAndUse(NONCE, taintedContext().ctx, { binding: VERIFIER });

    await expectCode(
      () => store.checkAndUse(NONCE, taintedContext().ctx, { binding: VERIFIER }),
      ErrorCodes.REPLAY_DETECTED,
    );
  });

  it('put / has も同じ 1 回読みで、発行と問い合わせのキー空間が揃う', async () => {
    const store = makeStore();
    // `put` が別キー空間へ発行記録を書くと、消費時に「未発行 nonce」として扱われる。
    await store.put(NONCE, taintedContext().ctx, 300_000);
    await store.checkAndUse(NONCE, PLAIN_CTX, { binding: VERIFIER });

    expect(await store.has(NONCE, taintedContext().ctx)).toBe(true);
    expect(await store.has(NONCE, EVIL_CTX)).toBe(false);
  });
});
