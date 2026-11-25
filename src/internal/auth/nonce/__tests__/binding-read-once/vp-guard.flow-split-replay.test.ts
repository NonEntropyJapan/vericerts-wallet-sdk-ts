/**
 * JWT-VP 経路（`verifyPresentationWithReplayGuard` → `store.ts`）で `flow` が**層間で分裂**しても
 * 消費記録が照合済みの flow のキー空間に載ることの回帰テスト。
 *
 * 欠陥の形と成立条件は KB-JWT 経路（`guard.flow-split-replay.test.ts` のヘッダ）と同じで、
 * 修正前は生の `nonceContext` を `checkAndUse` へ渡していたため store 層が `flow` を 2 回目として
 * 読み直し、**照合を通っていない 2 回目の flow** が拒否リストキーの接頭辞になっていた。
 * その結果、同じ nonce を素の `{ flow: 'oid4vp', clientId }` で再提示すると初見として受理された。
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
import { expectCode, multiFlowContext } from './binding-read-once.fixtures.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const AUD = 'https://verifier.example/client';
const IAT = 1_700_000_000;
/** VP 署名の検証鍵（holder = ES256）。 */
const HOLDER_KEY = { publicKeyJwk: FIXTURES.ES256.jwk } as const;
/** 素のデータだけを持つ正規のコンテキスト（分裂した flow の 1 回目と同じ flow）。 */
const PLAIN_CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };

/** 内包 VC を持たない JWT-VP を組み立てる（束縛検査とキー空間だけを見るため）。 */
function present(): string {
  return issuePresentation(sampleVp({ verifiableCredential: [] }), signerFor('ES256'), {
    audience: AUD,
    nonce: NONCE,
    nowSeconds: IAT,
  });
}

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => IAT * 1000 });
}

/** ガードを 1 回通す。 */
function guard(ctx: NonceContext, store: NonceStore): Promise<unknown> {
  return verifyPresentationWithReplayGuard(present(), {
    key: HOLDER_KEY,
    nonce: NONCE,
    nonceStore: store,
    nonceContext: ctx,
    nowSeconds: IAT,
  });
}

describe('vp-guard → store: flow が層間で分裂しても同一 nonce は 2 回消費できない', () => {
  it('分裂 flow で消費した nonce を素のコンテキストで再提示すると 4010', async () => {
    const store = makeStore();
    // `clientId` と `issuer` に同じ値を置く（どちらの束縛メンバが選ばれても `aud` 照合は
    // 成功するため、観測できる差は**キー接頭辞の flow だけ**になる）。
    const { ctx } = multiFlowContext({
      flows: ['oid4vp', 'oid4vci'],
      members: { clientId: AUD, issuer: AUD },
    });

    const verified = await guard(ctx, store);
    // guard の拒否は例外なので、ここでの前提は「例外なく検証済み envelope が返ること」。
    // 内包 VC ゼロの VP は `valid: false` / `3002` なので `valid` では見ない。
    expect((verified as { readonly holderDID: string }).holderDID).toBe('did:example:holder');

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
