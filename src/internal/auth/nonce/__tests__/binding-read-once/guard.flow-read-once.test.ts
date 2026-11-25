/**
 * KB-JWT 経路（`verifySdJwtWithReplayGuard`）が `flow` を **1 度だけ**読み、その同じ読み取り結果で
 * 窓選択と束縛メンバの選択を行うことの回帰テスト。
 *
 * **修正前の欠陥**: guard 層は 1 検証あたり `flow` を 2 回読んでいた。
 *
 * 1. `ownProperty<NonceFlow>(nonceContext, 'flow')`（own 読み可否のガード兼 replay-window の
 *    既定窓選択）
 * 2. `bindingValueOf(nonceContext)` の内部（`resolveFlow` による**束縛メンバの選択**）
 *
 * `flow` を own の**アクセサ**として持つコンテキストは読み取りごとに別値を返し得るため、
 * **窓選択に使う flow と束縛メンバの選択に使う flow が別 flow になり得た**。現在は入口で
 * コンテキストをデータスナップショットへ畳む（`context-snapshot.ts`）ので、元のコンテキストへの
 * 読み取りは検証全体で 1 回だけになり、層をまたいだ分裂も起こらない
 * （層間の分裂そのものは `guard.flow-split-replay.test.ts` が固定する）。
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
 *   （fail-closed は修正対象ではない）。単一読み化がこの 2 つを壊していないことを見張る
 *
 * 実鍵で SD-JWT VC を発行し、実際に KB-JWT を付けて提示する（モックは使わない）。
 */

import { describe, expect, it } from 'bun:test';
import {
  AUD,
  IAT,
  ISSUER_JWK,
  issue,
  SESSION_SIGNER,
} from '../../../../credential/sdjwt/__tests__/key-binding.fixtures.js';
import { addKeyBinding } from '../../../../credential/sdjwt/verify.js';
import { ErrorCodes } from '../../../../errors.js';
import { verifySdJwtWithReplayGuard } from '../../guard.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';
import {
  EVIL_BINDING,
  expectCode,
  multiFlowContext,
  snapshotStore,
} from './binding-read-once.fixtures.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';

/** KB-JWT 付きの提示を組み立てる（`aud` は常に正規の Verifier）。 */
function present(): string {
  return addKeyBinding(issue(), SESSION_SIGNER, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  });
}

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(nowSeconds = IAT): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => nowSeconds * 1000 });
}

/** ガードを 1 回通す（`nowSeconds` だけ差し替えられる）。 */
function guard(ctx: NonceContext, store: NonceStore, nowSeconds = IAT): Promise<unknown> {
  return verifySdJwtWithReplayGuard(present(), {
    issuerKey: ISSUER_JWK,
    nonce: NONCE,
    nonceContext: ctx,
    nonceStore: store,
    nowSeconds,
  });
}

describe('guard — flow は入口で 1 度だけ読む', () => {
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
    // 検証全体の総計。store 層はスナップショットを受け取るため元の ctx を読み直さない。
    // 修正前は guard 層 2 回 ＋ store 層 4 回（照合 / キー組み立て / 容量スコープ / 既定 TTL）
    // で総計 6 だった（`c6a010a^` で実測）。
    expect(flowReads()).toBe(1);
  });

  it('束縛メンバは窓選択と同じ 1 回目の読み取りの flow で選ぶ（2 回目の flow に従わない）', async () => {
    // 1 回目 `oid4vp`（束縛メンバ `clientId`）→ 窓選択もこの flow で行われる。
    // 2 回目 `oid4vci`（束縛メンバ `issuer`）。修正前は束縛メンバの選択だけが 2 回目に従い、
    // **攻撃者が仕込んだ `issuer` が期待 `aud`** になっていた（窓選択とは別 flow）。
    const { ctx } = multiFlowContext({
      flows: ['oid4vp', 'oid4vci'],
      members: { clientId: EVIL_BINDING, issuer: AUD },
    });

    // 修正前は `issuer`（= 実測 `aud` と一致）が期待値になり素通りしていた。
    await expectCode(() => guard(ctx, makeStore()), ErrorCodes.NONCE_BINDING_MISMATCH);
  });

  it('replay-window の窓も同じ 1 回目の flow で選ぶ（後続の広い窓は使われない）', async () => {
    // `oid4vp` の既定窓は ±30 s、`siopv2` は ±60 s。45 s ずれた提示は `oid4vp` の窓では
    // 圏外・`siopv2` の窓では圏内なので、どちらの flow で窓を選んだかが観測できる。
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
