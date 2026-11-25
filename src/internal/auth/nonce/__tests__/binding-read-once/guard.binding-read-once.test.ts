/**
 * KB-JWT 経路（`verifySdJwtWithReplayGuard` → `store.ts`）の**単一読み（read-once）**回帰テスト。
 *
 * JWT-VP 経路（`vp-guard.binding-read-once.test.ts`）と同じ store 層を共有するため、修正前の
 * 束縛メンバ読み取りも同じ 4 回構成で、**3 回目（`entryKeyOf` の拒否リストキー組み立て）だけが
 * 束縛照合を通っていない**読み取りだった。既存の KB-JWT テスト（`../nonce-guard.test.ts`）は
 * 素のデータ context しか使わないためこの経路差を検出できない。
 *
 * 主アサーションは JWT-VP 経路と同じく「素のコンテキストで `store.has` が真」にする
 * （理由は当該ファイルのヘッダ）。
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
import { verifySdJwtWithReplayGuard } from '../../guard.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStore } from '../../types.js';
import { EVIL_BINDING, taintedBindingContext } from './binding-read-once.fixtures.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const PLAIN_CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };
const EVIL_CTX: NonceContext = { flow: 'oid4vp', clientId: EVIL_BINDING };

/** KB-JWT 付きの提示を組み立てる。 */
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

describe('guard → store: 消費記録は照合済み束縛値のキー空間に載る', () => {
  it('拒否リストキー組み立ての読み取り回を汚染しても、記録先は照合済み束縛値のキー空間', async () => {
    const store = makeStore();
    // 修正前に `entryKeyOf` が使っていた 3 回目だけを汚染する（1・2 回目は照合に使われるため
    // 正規値を返し、KB-JWT の `aud` 照合は成功させる）。
    const { ctx, reads } = taintedBindingContext({
      flow: 'oid4vp',
      member: 'clientId',
      value: AUD,
      taintedRead: 3,
    });

    const verified = await verifySdJwtWithReplayGuard(present(), {
      issuerKey: ISSUER_JWK,
      nonce: NONCE,
      nonceContext: ctx,
      nonceStore: store,
      nowSeconds: IAT,
    });
    expect(verified.keyBindingVerified).toBe(true);

    // 主アサーション: 修正前はここが false（消費記録が攻撃者のキー空間にあり、拒否リストに
    // 載らなかった）。
    expect(await store.has(NONCE, PLAIN_CTX)).toBe(true);
    expect(await store.has(NONCE, EVIL_CTX)).toBe(false);
    // 入口のスナップショット（`context-snapshot.ts`）の 1 回だけ。store 層はスナップショットを
    // 受け取るため元の ctx を読み直さず、汚染した 3 回目には到達しない（修正前の総計は 4 回）。
    expect(reads()).toBe(1);
  });
});
