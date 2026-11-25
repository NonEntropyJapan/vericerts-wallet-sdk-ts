/**
 * `verifyPresentationWithReplayGuard` の束縛値検査を KB-JWT 経路へ
 * 追随させたことの回帰テスト。
 *
 * **修正前の欠陥 (a)**: `assertBinding(nonceContext, opts.expectedAudience)` と
 * `assertBinding(nonceContext, aud)` を続けて呼んでいたため `bindingValueOf` が **2 回**走り、
 * `flow` / 束縛メンバを own のアクセサとして持つ `NonceContext` では読み取りごとに別値が返り得た
 * （`context.ts` 冒頭が明記する TOCTOU）。照合した値と実測 `aud` を照合する値がズレる。
 *
 * (a) の読み取り回数は **検証全体の総計**で数える。
 * 消費記録のキー空間も照合済みの flow と一致することを
 * `../binding-read-once/` が固定する。
 *
 * **修正前の欠陥 (b)**: `guard.ts` が持つ「束縛値が空文字なら 4012」のガードが本経路に無く、
 * 空 `clientId` の context と空 `aud` の JWT-VP の組み合わせで束縛検査が「一致」して素通りしていた
 * （下流の内包 VC 検証の fail-closed に頼るため、失敗面が経路間で非対称だった）。
 *
 * 実鍵のみを使う（モック禁止）。VP holder は ES256。
 */

import { describe, expect, it } from 'bun:test';
import {
  FIXTURES,
  sampleVp,
  signerFor,
} from '../../../../credential/presentation/__tests__/presentation.fixtures.js';
import { issuePresentation } from '../../../../credential/presentation/issue.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';
import { verifyPresentationWithReplayGuard } from '../../vp-guard.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const AUD = 'https://verifier.example/client';
const IAT = 1_700_000_000;
/** VP 署名の検証鍵（holder = ES256）。 */
const HOLDER_KEY = { publicKeyJwk: FIXTURES.ES256.jwk } as const;

/** 内包 VC を持たない JWT-VP を組み立てる（束縛検査だけを見るため）。 */
function presentTo(audience: string): string {
  return issuePresentation(sampleVp({ verifiableCredential: [] }), signerFor('ES256'), {
    audience,
    nonce: NONCE,
    nowSeconds: IAT,
  });
}

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => IAT * 1000 });
}

/**
 * `flow` と束縛メンバ `clientId` を own の**アクセサ**として持つ `NonceContext` を作る。
 *
 * `context.ts` 冒頭が TOCTOU の前提として挙げるのがこの形の context で、読み取りごとに別値を
 * 返し得る。ここでは値は固定し、**読み取り回数だけ**を観測する。
 */
function accessorContext(value: string): {
  readonly ctx: NonceContext;
  readonly reads: () => number;
  readonly flowReads: () => number;
} {
  let reads = 0;
  let flowReads = 0;
  const ctx = {} as unknown as NonceContext;
  Object.defineProperty(ctx, 'flow', {
    get(): string {
      flowReads += 1;
      return 'oid4vp';
    },
    enumerable: true,
    configurable: true,
  });
  Object.defineProperty(ctx, 'clientId', {
    get(): string {
      reads += 1;
      return value;
    },
    enumerable: true,
    configurable: true,
  });
  return { ctx, reads: () => reads, flowReads: () => flowReads };
}

/**
 * `checkAndUse` に入った時点の読み取り回数を記録する `NonceStore` ラッパ。
 *
 * 検証全体の総読み取り回数は呼び出し元がテスト末尾で数える。本ラッパはそこから
 * **store 層へ入る前までの分**を切り出すためのもので、`checkAndUse` 突入時点の
 * カウンタ値を返す。
 */
function countingStore(reads: () => number): {
  readonly store: NonceStore;
  readonly readsAtConsume: () => number | undefined;
} {
  const base = makeStore();
  let at: number | undefined;
  const store: NonceStore = {
    generate: (byteLength) => base.generate(byteLength),
    put: (nonce, ctx, ttlMs) => base.put(nonce, ctx, ttlMs),
    checkAndUse: (nonce, ctx, opts) => {
      at = reads();
      return base.checkAndUse(nonce, ctx, opts);
    },
    has: (nonce, ctx) => base.has(nonce, ctx),
    prune: () => base.prune(),
  };
  return { store, readsAtConsume: () => at };
}

/** 送出された `VericertsError` のコードを取り出す（例外が出なければ `undefined`）。 */
async function thrownCode(fn: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await fn();
    return undefined;
  } catch (error) {
    return error instanceof VericertsError ? error.code : String(error);
  }
}

describe('vp-guard — 束縛値は入口で 1 度だけ読む', () => {
  it('expectedAudience 併用時も検証全体で 1 回に収まる', async () => {
    const { ctx, reads, flowReads } = accessorContext(AUD);
    const { store, readsAtConsume } = countingStore(reads);
    const verified = await verifyPresentationWithReplayGuard(presentTo(AUD), {
      key: HOLDER_KEY,
      nonce: NONCE,
      nonceStore: store,
      nonceContext: ctx,
      nowSeconds: IAT,
      expectedAudience: AUD,
    });
    // guard の拒否は例外なので、ここでの前提は「例外なく検証済み envelope が返ること」。
    // 内包 VC ゼロの VP は `valid: false` / `3002` なので `valid` では見ない。
    expect(verified.holderDID).toBe('did:example:holder');

    // 不変条件: 束縛値は**1 度だけ**読み、
    // 照合とキー組み立てに**同じ読み取り結果**を使う。読み直すと、束縛照合を通っていない値から
    // 拒否リストキーが決まり、検証済み束縛値とは別のキー空間へ消費記録が書かれる
    // （＝リプレイ可能なまま残る）。
    //
    // 読み取りは入口のスナップショット（`context-snapshot.ts`）の 1 回だけで、それは
    // `checkAndUse` 突入より前に済む。修正前は guard 層が `assertBinding` を 2 回呼んで 2 回、
    // store 層が照合・キー組み立て・容量スコープで 3 回読んで総計 4 回だった。
    expect(readsAtConsume()).toBe(1);
    // 検証全体の総計。store 層はスナップショットを受け取るので元の ctx を読み直さない。
    expect(reads()).toBe(1);
    // `flow` も束縛値と同じく入口の 1 回だけ。窓選択・束縛メンバの選択・拒否リストキーの
    // すべてが同じ読み取り結果に基づくことは `../binding-read-once/` が固定する。修正前は
    // guard 層が 2 回（`bindingValueOf` が内部で読み直していた）・store 層が 4 回（照合 /
    // キー組み立て / 容量スコープ / 既定 TTL）で総計 6 だった。
    expect(flowReads()).toBe(1);
  });
});

describe('vp-guard — 束縛値が空文字なら 4012', () => {
  it('空 clientId の context と空 aud の JWT-VP で 4012（素通りさせない）', async () => {
    // 前提: `aud` も束縛値も空文字なので、単純な値比較なら「一致」して束縛検査を素通りする。
    // 修正前はここが例外にならず `valid: true` で返っていた（内包 VC が無いため下流の
    // fail-closed も働かない）。
    expect(
      await thrownCode(() =>
        verifyPresentationWithReplayGuard(presentTo(''), {
          key: HOLDER_KEY,
          nonce: NONCE,
          nonceStore: makeStore(),
          nonceContext: { flow: 'oid4vp', clientId: '' },
          nowSeconds: IAT,
        }),
      ),
    ).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
  });

  it('空 clientId は expectedAudience を空文字で併用しても 4012', async () => {
    expect(
      await thrownCode(() =>
        verifyPresentationWithReplayGuard(presentTo(''), {
          key: HOLDER_KEY,
          nonce: NONCE,
          nonceStore: makeStore(),
          nonceContext: { flow: 'oid4vp', clientId: '' },
          nowSeconds: IAT,
          expectedAudience: '',
        }),
      ),
    ).toBe(ErrorCodes.NONCE_BINDING_MISMATCH);
  });

  it('非空の束縛値は従来どおり通る（過剰な拒否をしない）', async () => {
    const verified = await verifyPresentationWithReplayGuard(presentTo(AUD), {
      key: HOLDER_KEY,
      nonce: NONCE,
      nonceStore: makeStore(),
      nonceContext: { flow: 'oid4vp', clientId: AUD },
      nowSeconds: IAT,
    });
    // guard の拒否は例外なので、ここでの前提は「例外なく検証済み envelope が返ること」。
    // 内包 VC ゼロの VP は `valid: false` / `3002` なので `valid` では見ない。
    expect(verified.holderDID).toBe('did:example:holder');
  });
});
