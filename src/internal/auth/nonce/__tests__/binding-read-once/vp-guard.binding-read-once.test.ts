/**
 * JWT-VP 経路（`verifyPresentationWithReplayGuard` → `store.ts`）の**単一読み（read-once）**
 * 回帰テスト。
 *
 * `store.binding-read-once.test.ts` が固定した store 層の不変条件が、guard 層を通した実経路でも
 * 成立することを確認する。修正前の束縛メンバ読み取りは 1 検証あたり 4 回で、
 *
 * 1. `vp-guard.ts` の `bindingValueOf`（照合用）
 * 2. store の `assertBinding`（照合用）
 * 3. store の `entryKeyOf`（**拒否リストキー組み立て**）
 * 4. `NonceCapacityManager#enforceCapacity`（容量スコープ）
 *
 * 3 が「束縛照合を一度も通っていない読み取り値」だった。よって 3 回目だけを汚染すると、
 * 検証は成功しつつ消費記録が別キー空間へ書かれる（＝同じ nonce がリプレイ可能なまま残る）。
 *
 * **主アサーションは「素のコンテキストで `store.has` が真」**にする。「2 回目の提示が 4010」を
 * 直接アサートすると、読み取り回数のパリティが層構成の変更で動いたときに 4012 にも転び得て、
 * 検証したい不変条件（消費記録が検証済み束縛値のキー空間にあること）から外れる。
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
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';
import { verifyPresentationWithReplayGuard } from '../../vp-guard.js';
import { EVIL_BINDING, taintedBindingContext } from './binding-read-once.fixtures.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const AUD = 'https://verifier.example/client';
const IAT = 1_700_000_000;
/** VP 署名の検証鍵（holder = ES256）。 */
const HOLDER_KEY = { publicKeyJwk: FIXTURES.ES256.jwk } as const;

const PLAIN_CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };
const EVIL_CTX: NonceContext = { flow: 'oid4vp', clientId: EVIL_BINDING };

/** 内包 VC を持たない JWT-VP を組み立てる（束縛検査とキー空間だけを見るため）。 */
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

describe('vp-guard → store: 消費記録は照合済み束縛値のキー空間に載る', () => {
  it('拒否リストキー組み立ての読み取り回を汚染しても、記録先は照合済み束縛値のキー空間', async () => {
    const store = makeStore();
    // 修正前に `entryKeyOf` が使っていた 3 回目だけを汚染する（1・2 回目は照合に使われるため
    // 正規値を返し、検証自体は成功させる）。
    const { ctx, reads } = taintedBindingContext({
      flow: 'oid4vp',
      member: 'clientId',
      value: AUD,
      taintedRead: 3,
    });

    const verified = await verifyPresentationWithReplayGuard(presentTo(AUD), {
      key: HOLDER_KEY,
      nonce: NONCE,
      nonceStore: store,
      nonceContext: ctx,
      nowSeconds: IAT,
    });
    // guard の拒否は例外なので、ここでの前提は「例外なく検証済み envelope が返ること」。
    // 内包 VC ゼロの VP は `valid: false` / `3002` なので `valid` では見ない。
    expect(verified.holderDID).toBe('did:example:holder');

    // 主アサーション: 修正前はここが false（消費記録が攻撃者のキー空間にあり、拒否リストに
    // 載らなかった）。
    expect(await store.has(NONCE, PLAIN_CTX)).toBe(true);
    expect(await store.has(NONCE, EVIL_CTX)).toBe(false);
    // 入口のスナップショット（`context-snapshot.ts`）の 1 回だけ。store 層はスナップショットを
    // 受け取るため元の ctx を読み直さず、汚染した 3 回目には到達しない（修正前の総計は 4 回）。
    expect(reads()).toBe(1);
  });

  it('expectedAudience を併用しても記録先は変わらない（照合回数が増えてもキー空間は同じ）', async () => {
    const store = makeStore();
    const { ctx } = taintedBindingContext({
      flow: 'oid4vp',
      member: 'clientId',
      value: AUD,
      taintedRead: 3,
    });

    await verifyPresentationWithReplayGuard(presentTo(AUD), {
      key: HOLDER_KEY,
      nonce: NONCE,
      nonceStore: store,
      nonceContext: ctx,
      nowSeconds: IAT,
      expectedAudience: AUD,
    });

    expect(await store.has(NONCE, PLAIN_CTX)).toBe(true);
    expect(await store.has(NONCE, EVIL_CTX)).toBe(false);
  });
});
