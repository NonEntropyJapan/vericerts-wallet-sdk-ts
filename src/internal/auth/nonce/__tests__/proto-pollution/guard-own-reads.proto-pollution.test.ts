/**
 * `verifySdJwtWithReplayGuard` の関数内読み取りを own 限定へ揃えたことの回帰テスト。
 *
 * `nowSeconds` / `replayWindowSeconds` / `nonceTtlMs` だけを own 化しても、同じ関数の他の読み取りが
 * プロトタイプ鎖のままだと、そのプロパティを**省略した**正当な呼び出しで `Object.prototype` の
 * 汚染値が採用される。とくに `aud` / `iat` を持たない KB-JWT は、汚染値によって
 * 「バインディング一致」「リプレイ窓内」に化ける（fail-open）。
 *
 * 汚染と無関係に通るテストは無価値なので、検証はすべて「そのプロパティを省略した入力」で行う。
 * 併せて、`nonceStore` を own 限定で読んでいない（＝プロトタイプメソッドの class DI が
 * 無言で未指定扱いにならない）ことも確認する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import {
  AUD,
  IAT,
  ISSUER_JWK,
  issue,
  SESSION_SIGNER,
  signAsSession,
  toCompactKbJwt,
} from '../../../../credential/sdjwt/__tests__/key-binding.fixtures.js';
import { addKeyBinding } from '../../../../credential/sdjwt/verify.js';
import { decodeCompactJws } from '../../../../credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { type ReplayGuardOptions, verifySdJwtWithReplayGuard } from '../../guard.js';
import { createNonceStore } from '../../store.js';
import type { CheckAndUseOptions, NonceContext, NonceStore } from '../../types.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const OTHER_AUD = 'https://evil.example/client';
const CTX: NonceContext = { flow: 'oid4vp', clientId: AUD };

/** `checkAndUse` を**プロトタイプメソッド**として公開するストア（class DI の正当な形）。 */
class PrototypeMethodNonceStore {
  readonly #inner: NonceStore;

  constructor(inner: NonceStore) {
    this.#inner = inner;
  }

  checkAndUse(nonce: string, ctx: NonceContext, opts?: CheckAndUseOptions): Promise<void> {
    return this.#inner.checkAndUse(nonce, ctx, opts);
  }
}

/** 固定時刻の `NonceStore` を作る。 */
function makeStore(): NonceStore {
  return createNonceStore({ backend: 'memory', now: () => IAT * 1000 });
}

/** 既定の KB-JWT 付き提示。 */
function present(): string {
  return addKeyBinding(issue(), SESSION_SIGNER, { nonce: NONCE, audience: AUD, iatSeconds: IAT });
}

/** KB-JWT payload から指定クレームを取り除いた提示（署名は張り替えるので KB 検証は通る）。 */
function presentWithoutKbClaims(...omit: readonly string[]): string {
  const full = present();
  const separator = full.lastIndexOf('~');
  const kbJwt = full.slice(separator + 1);
  const headerSeg = kbJwt.slice(0, kbJwt.indexOf('.'));
  const payload: Record<string, unknown> = { ...decodeCompactJws(kbJwt).payload };
  for (const key of omit) {
    delete payload[key];
  }
  const payloadSeg = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${headerSeg}.${payloadSeg}`;
  return `${full.slice(0, separator + 1)}${toCompactKbJwt(signingInput, signAsSession(signingInput))}`;
}

/** 全プロパティを揃えたオプション。 */
function guardOpts(store: NonceStore): ReplayGuardOptions {
  return {
    issuerKey: ISSUER_JWK,
    nonce: NONCE,
    nonceContext: CTX,
    nonceStore: store,
    nowSeconds: IAT,
  };
}

/** 必須プロパティを 1 つ省いたオプション（型では省略できないためキャストする）。 */
function omitting(store: NonceStore, key: string): ReplayGuardOptions {
  const opts: Record<string, unknown> = { ...guardOpts(store) };
  delete opts[key];
  return opts as unknown as ReplayGuardOptions;
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

describe('verifySdJwtWithReplayGuard: opts の own 限定読み取り', () => {
  it('nonce を省略した呼び出しで継承 nonce を消費しない', async () => {
    const store = makeStore();
    await withPollutedPrototypeAsync({ nonce: NONCE }, async () => {
      await expectCode(
        () => verifySdJwtWithReplayGuard(present(), omitting(store, 'nonce')),
        ErrorCodes.NONCE_MALFORMED,
      );
    });
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('nonceContext を省略した呼び出しで継承コンテキストを束縛対象にしない', async () => {
    const store = makeStore();
    await withPollutedPrototypeAsync({ nonceContext: CTX }, async () => {
      await expectCode(
        () => verifySdJwtWithReplayGuard(present(), omitting(store, 'nonceContext')),
        ErrorCodes.NONCE_BINDING_MISMATCH,
      );
    });
  });

  it('flow を持たない nonceContext で継承 flow を採用しない', async () => {
    const store = makeStore();
    const opts = {
      ...guardOpts(store),
      nonceContext: { clientId: AUD } as unknown as NonceContext,
    };
    await withPollutedPrototypeAsync({ flow: 'oid4vp' }, async () => {
      await expectCode(
        () => verifySdJwtWithReplayGuard(present(), opts),
        ErrorCodes.NONCE_BINDING_MISMATCH,
      );
    });
  });

  it('nonceStore を省略した呼び出しで継承ストアへ消費を委譲しない', async () => {
    const store = makeStore();
    let delegated = false;
    const forged = {
      checkAndUse: (): Promise<void> => {
        delegated = true;
        return Promise.resolve();
      },
    };
    await withPollutedPrototypeAsync({ nonceStore: forged }, async () => {
      await expectCode(
        () => verifySdJwtWithReplayGuard(present(), omitting(store, 'nonceStore')),
        ErrorCodes.REPLAY_DETECTED,
      );
    });
    expect(delegated).toBe(false);
  });

  it('checkAndUse を持たない nonceStore は継承した消費関数へ委譲しない', async () => {
    // `nonceStore` は own（＝「ストアはある」）だが `checkAndUse` を持たない。鎖読みだと
    // `Object.prototype.checkAndUse` が「消費手段あり」に化け、攻撃者の関数が消費を
    // 完了したことにして提示が受理される（fail-open）。
    const store = makeStore();
    let delegated = false;
    const forgedCheckAndUse = (): Promise<void> => {
      delegated = true;
      return Promise.resolve();
    };
    const opts = { ...guardOpts(store), nonceStore: {} as unknown as NonceStore };
    await withPollutedPrototypeAsync({ checkAndUse: forgedCheckAndUse }, async () => {
      await expectCode(
        () => verifySdJwtWithReplayGuard(present(), opts),
        ErrorCodes.REPLAY_DETECTED,
      );
    });
    expect(delegated).toBe(false);
  });

  it('audience を省略した呼び出しは継承 audience との照合で落ちない（正常系）', async () => {
    const store = makeStore();
    const verified = await withPollutedPrototypeAsync({ audience: OTHER_AUD }, () =>
      verifySdJwtWithReplayGuard(present(), guardOpts(store)),
    );
    expect(verified.keyBindingVerified).toBe(true);
  });
});

describe('verifySdJwtWithReplayGuard: KB-JWT payload の own 限定読み取り', () => {
  it('aud を持たない KB-JWT は継承 aud でバインディング一致に化けない', async () => {
    const store = makeStore();
    const presented = presentWithoutKbClaims('aud');
    await withPollutedPrototypeAsync({ aud: AUD }, async () => {
      await expectCode(
        () => verifySdJwtWithReplayGuard(presented, guardOpts(store)),
        ErrorCodes.NONCE_BINDING_MISMATCH,
      );
    });
    expect(await store.has(NONCE, CTX)).toBe(false);
  });

  it('iat を持たない KB-JWT は継承 iat でリプレイ窓内に化けない', async () => {
    const store = makeStore();
    const presented = presentWithoutKbClaims('iat');
    await withPollutedPrototypeAsync({ iat: IAT }, async () => {
      await expectCode(
        () => verifySdJwtWithReplayGuard(presented, guardOpts(store)),
        ErrorCodes.CLOCK_SKEW_EXCEEDED,
      );
    });
    expect(await store.has(NONCE, CTX)).toBe(false);
  });
});

describe('verifySdJwtWithReplayGuard: own 化しすぎの回帰検出', () => {
  it('checkAndUse をプロトタイプメソッドで実装した class DI でも nonce を消費する', async () => {
    const inner = makeStore();
    const store = new PrototypeMethodNonceStore(inner) as unknown as NonceStore;
    const verified = await verifySdJwtWithReplayGuard(present(), guardOpts(store));
    expect(verified.keyBindingVerified).toBe(true);
    expect(await inner.has(NONCE, CTX)).toBe(true);
  });
});
