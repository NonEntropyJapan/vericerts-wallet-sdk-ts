/**
 * `binding-read-once` テスト群の共有フィクスチャ。
 *
 * 3 経路（store 直叩き / JWT-VP / KB-JWT）で同じ汚染コンテキストを使うため、
 * 「特定の読み取り回だけ攻撃者の値を返す `NonceContext`」の組み立てをここに 1 つだけ置く。
 *
 * - `taintedBindingContext`: 束縛メンバの特定の読み取り回だけ攻撃者の値を返す。
 * - `multiFlowContext`: `flow` の読み取り回ごとに別の flow を返す（層内の読み直しを検出する）。
 * - `snapshotStore`: `checkAndUse` 突入時点の読み取り回数を記録し、guard 層の分を切り出す。
 */

import { expect } from 'bun:test';
import { VericertsError } from '../../../../errors.js';
import type { NonceContext, NonceStore } from '../../types.js';

/** 汚染した読み取り回だけ返る攻撃者の値。どの経路でも正規値と別のキー空間になる。 */
export const EVIL_BINDING = 'https://evil.example/client';

/**
 * 束縛メンバを own の**アクセサ**として持ち、指定した読み取り回だけ別値を返す
 * `NonceContext` を作る。
 *
 * `context.ts` 冒頭が TOCTOU の前提として挙げるのがこの形の context で、読み取りごとに別値を
 * 返し得る。照合を通す回は正規値を返し、キー組み立てに使われる回だけ汚染する。
 *
 * @param opts.flow コンテキストの flow。
 * @param opts.member flow に対応する束縛メンバ名（`oid4vp` なら `clientId`）。
 * @param opts.value 汚染回以外で返す正規の束縛値。
 * @param opts.taintedRead 攻撃者の値を返す読み取り回（1 始まり）。
 * @returns 汚染コンテキストと、これまでの束縛メンバ読み取り回数。
 */
export function taintedBindingContext(opts: {
  readonly flow: string;
  readonly member: string;
  readonly value: string;
  readonly taintedRead: number;
}): { readonly ctx: NonceContext; readonly reads: () => number } {
  let reads = 0;
  const ctx = { flow: opts.flow } as unknown as NonceContext;
  Object.defineProperty(ctx, opts.member, {
    get(): string {
      reads += 1;
      return reads === opts.taintedRead ? EVIL_BINDING : opts.value;
    },
    enumerable: true,
    configurable: true,
  });
  return { ctx, reads: () => reads };
}

/**
 * `VericertsError` の code を検査する（非同期版。既存 nonce テスト群と同じ形）。
 *
 * @param fn 検査対象の呼び出し。
 * @param code 期待する `ErrorCodes` の値。
 */
export async function expectCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(code as never);
    return;
  }
  throw new Error('例外が送出されなかった');
}

/**
 * `flow` を own の**アクセサ**として持ち、読み取り回ごとに別の flow を返す `NonceContext` を作る。
 *
 * 単一読み規則が守られているかは「どの読み取り回の flow が使われたか」で観測できる。
 * `flows[0]` は 1 回目の読み取りで返り、以降は添字を進め、末尾に達したらその値を返し続ける。
 *
 * @param opts.flows 読み取り回ごとに返す flow（1 始まりの読み取り回に対応）。
 * @param opts.members 束縛メンバ名 → 値の対応（`clientId` / `issuer` 等を素のデータで持たせる）。
 * @returns 汚染コンテキストと、これまでの `flow` 読み取り回数。
 */
export function multiFlowContext(opts: {
  readonly flows: readonly string[];
  readonly members: Readonly<Record<string, string>>;
}): { readonly ctx: NonceContext; readonly flowReads: () => number } {
  let flowReads = 0;
  const ctx = { ...opts.members } as unknown as NonceContext;
  Object.defineProperty(ctx, 'flow', {
    get(): string {
      flowReads += 1;
      return opts.flows[Math.min(flowReads - 1, opts.flows.length - 1)] as string;
    },
    enumerable: true,
    configurable: true,
  });
  return { ctx, flowReads: () => flowReads };
}

/**
 * `checkAndUse` 突入時点のカウンタ値を記録する `NonceStore` ラッパ。
 *
 * 検証全体の読み取り回数から **guard 層だけの分**を切り出すために使う（突入時点の
 * スナップショット＝store 層へ入る前までの回数）。
 *
 * @param base 実処理を委譲する `NonceStore`。
 * @param counter 観測対象の読み取りカウンタ。
 * @returns ラップした store と、`checkAndUse` 突入時点のカウンタ値。
 */
export function snapshotStore(
  base: NonceStore,
  counter: () => number,
): { readonly store: NonceStore; readonly atConsume: () => number | undefined } {
  let at: number | undefined;
  const store: NonceStore = {
    generate: (byteLength) => base.generate(byteLength),
    put: (nonce, ctx, ttlMs) => base.put(nonce, ctx, ttlMs),
    checkAndUse: (nonce, ctx, opts) => {
      at = counter();
      return base.checkAndUse(nonce, ctx, opts);
    },
    has: (nonce, ctx) => base.has(nonce, ctx),
    prune: () => base.prune(),
  };
  return { store, atConsume: () => at };
}
