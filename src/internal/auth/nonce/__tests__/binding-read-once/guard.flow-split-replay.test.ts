/**
 * KB-JWT 経路（`verifySdJwtWithReplayGuard` → `store.ts`）で `flow` が**層間で分裂**しても
 * 消費記録が照合済みの flow のキー空間に載ることの回帰テスト。
 *
 * **修正前の欠陥（実在のリプレイ経路）**: guard 層は生の `nonceContext` をそのまま
 * `checkAndUse` へ渡していたため、store 層の `resolveBinding` が `flow` を**2 回目として
 * 読み直して**いた。この 2 回目の `flow` はどことも照合されないまま拒否リストキーの接頭辞に
 * なるため、`flow` を own の**アクセサ**として持つ context で次が成立した。
 *
 * 1. guard 層: `flow` 1 回目 `oid4vp` → 束縛メンバ `clientId` ＝ 実測 `aud` で照合成功
 *    （replay-window も `oid4vp` の窓）
 * 2. store 層: `flow` 2 回目 `oid4vci` → 束縛メンバ `issuer` も同じ値なので
 *    `assertBindingMatches` も成功 → **キー接頭辞だけが `oid4vci:` になる**
 * 3. 同じ nonce を素の `{ flow: 'oid4vp', clientId }` で再提示 → キーは `oid4vp:` で引かれ、
 *    消費記録が見つからず「初見」として受理される（＝**同一 nonce の 2 回消費**）
 *
 * 修正後は guard 層の入口で `NonceContext` を own 限定のデータスナップショットへ畳み、以降は
 * store 層まで同じスナップショットを使うため、2 回目の読み取り自体が存在しない。
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
import { expectCode, multiFlowContext } from './binding-read-once.fixtures.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
/** 素のデータだけを持つ正規のコンテキスト（分裂した flow の 1 回目と同じ flow）。 */
const PLAIN_CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };

/** KB-JWT 付きの提示を組み立てる（`aud` は常に正規の Verifier）。 */
function present(): string {
  return addKeyBinding(issue(), SESSION_SIGNER, {
    nonce: NONCE,
    audience: AUD,
    iatSeconds: IAT,
  });
}

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => IAT * 1000 });
}

/** ガードを 1 回通す。 */
function guard(ctx: NonceContext, store: NonceStore): Promise<unknown> {
  return verifySdJwtWithReplayGuard(present(), {
    issuerKey: ISSUER_JWK,
    nonce: NONCE,
    nonceContext: ctx,
    nonceStore: store,
    nowSeconds: IAT,
  });
}

describe('guard → store: flow が層間で分裂しても同一 nonce は 2 回消費できない', () => {
  it('分裂 flow で消費した nonce を素のコンテキストで再提示すると 4010', async () => {
    const store = makeStore();
    // `clientId` と `issuer` に同じ値を置く（どちらの束縛メンバが選ばれても `aud` 照合は
    // 成功するため、観測できる差は**キー接頭辞の flow だけ**になる）。
    const { ctx } = multiFlowContext({
      flows: ['oid4vp', 'oid4vci'],
      members: { clientId: AUD, issuer: AUD },
    });

    const verified = await guard(ctx, store);
    expect((verified as { readonly keyBindingVerified: boolean }).keyBindingVerified).toBe(true);

    // 主アサーション: 修正前はここが例外にならず、同じ nonce が 2 回消費できていた。
    await expectCode(() => guard(PLAIN_CTX, store), ErrorCodes.REPLAY_DETECTED);
  });

  it('消費記録は照合に使った 1 回目の flow のキー空間に載る', async () => {
    const store = makeStore();
    const { ctx } = multiFlowContext({
      flows: ['oid4vp', 'oid4vci'],
      members: { clientId: AUD, issuer: AUD },
    });

    await guard(ctx, store);

    // 修正前は `oid4vci:` 側に載っていた（＝ `oid4vp:` を引く再提示が初見に見えた）。
    expect(await store.has(NONCE, PLAIN_CTX)).toBe(true);
    expect(await store.has(NONCE, { flow: 'oid4vci', issuer: AUD })).toBe(false);
  });
});
