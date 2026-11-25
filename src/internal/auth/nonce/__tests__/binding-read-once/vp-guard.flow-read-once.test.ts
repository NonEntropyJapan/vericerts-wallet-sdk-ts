/**
 * JWT-VP 経路（`verifyPresentationWithReplayGuard`）が `flow` を **1 度だけ**読み、その同じ
 * 読み取り結果で窓選択と束縛メンバの選択を行うことの回帰テスト。
 *
 * 欠陥の形は KB-JWT 経路（`guard.flow-read-once.test.ts` のヘッダ）と同じで、修正前は
 * 「own 読み可否のガード兼 replay-window の既定窓選択」と `bindingValueOf` 内の
 * 束縛メンバ選択で `flow` を 2 回読んでいた。現在は入口でコンテキストをデータスナップショットへ
 * 畳む（`context-snapshot.ts`）ので、元のコンテキストへの読み取りは検証全体で 1 回だけになる。
 *
 * ## 各 `it` の位置づけ（修正前の版へ戻して実測）
 *
 * 修正前の実装（`c6a010a^`）へ戻して 4 件を実測すると、2 件は fail・2 件は green だった。
 * 後者は欠陥の再現ではなく**不変条件の見張り（negative control）**である。
 *
 * - **回帰テスト（修正前は fail）**: 「flow の読み取りは入口の 1 回だけ」/「束縛メンバは窓選択と
 *   同じ 1 回目の読み取りの flow で選ぶ」
 * - **negative control（修正前も green）**: 「replay-window の窓も同じ 1 回目の flow で選ぶ」
 *   （窓選択は修正前も 1 回目の読み取りで行われていた）/「未知 flow は引き続き 4012」
 *   （fail-closed は修正対象ではない）
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
import { ErrorCodes } from '../../../../errors.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';
import { verifyPresentationWithReplayGuard } from '../../vp-guard.js';
import {
  EVIL_BINDING,
  expectCode,
  multiFlowContext,
  snapshotStore,
} from './binding-read-once.fixtures.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const AUD = 'https://verifier.example/client';
const IAT = 1_700_000_000;
/** VP 署名の検証鍵（holder = ES256）。 */
const HOLDER_KEY = { publicKeyJwk: FIXTURES.ES256.jwk } as const;

/** 内包 VC を持たない JWT-VP を組み立てる（束縛検査と窓選択だけを見るため）。 */
function present(): string {
  return issuePresentation(sampleVp({ verifiableCredential: [] }), signerFor('ES256'), {
    audience: AUD,
    nonce: NONCE,
    nowSeconds: IAT,
  });
}

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(nowSeconds = IAT): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => nowSeconds * 1000 });
}

/** ガードを 1 回通す（`nowSeconds` だけ差し替えられる）。 */
function guard(ctx: NonceContext, store: NonceStore, nowSeconds = IAT): Promise<unknown> {
  return verifyPresentationWithReplayGuard(present(), {
    key: HOLDER_KEY,
    nonce: NONCE,
    nonceStore: store,
    nonceContext: ctx,
    nowSeconds,
  });
}

describe('vp-guard — flow は入口で 1 度だけ読む', () => {
  it('flow の読み取りは入口の 1 回だけ（検証全体でも 1 回）', async () => {
    const { ctx, flowReads } = multiFlowContext({
      flows: ['oid4vp'],
      members: { clientId: AUD },
    });
    const { store, atConsume } = snapshotStore(makeStore(), flowReads);

    await guard(ctx, store);

    // 消費（store 層）へ入る前までの分。読み取りは入口のスナップショットの 1 回だけ。
    // 修正前は「own 読み可否ガード」＋「束縛メンバ選択」で 2 だった。
    expect(atConsume()).toBe(1);
    // 検証全体の総計。store 層はスナップショットを受け取るため元の ctx を読み直さない
    // （修正前は guard 層 2 回 ＋ store 層 4 回で総計 6）。
    expect(flowReads()).toBe(1);
  });

  it('束縛メンバは窓選択と同じ 1 回目の読み取りの flow で選ぶ（2 回目の flow に従わない）', async () => {
    // 修正前は束縛メンバの選択だけが 2 回目の flow（`oid4vci` → `issuer`）に従い、窓選択に
    // 使った flow（`oid4vp`）とは別 flow の束縛メンバが期待 `aud` になっていた。
    const { ctx } = multiFlowContext({
      flows: ['oid4vp', 'oid4vci'],
      members: { clientId: EVIL_BINDING, issuer: AUD },
    });

    await expectCode(() => guard(ctx, makeStore()), ErrorCodes.NONCE_BINDING_MISMATCH);
  });

  it('replay-window の窓も同じ 1 回目の flow で選ぶ（後続の広い窓は使われない）', async () => {
    // `oid4vp` の既定窓は ±30 s、`siopv2` は ±60 s。45 s ずれた提示でどちらを選んだか分かる。
    const { ctx } = multiFlowContext({
      flows: ['oid4vp', 'siopv2'],
      members: { clientId: AUD },
    });

    await expectCode(
      () => guard(ctx, makeStore(IAT + 45), IAT + 45),
      ErrorCodes.CLOCK_SKEW_EXCEEDED,
    );
  });

  it('未知 flow は引き続き 4012（fail-closed は失われない）', async () => {
    const ctx = { flow: 'evil-flow', clientId: AUD } as unknown as NonceContext;

    await expectCode(() => guard(ctx, makeStore()), ErrorCodes.NONCE_BINDING_MISMATCH);
  });
});
