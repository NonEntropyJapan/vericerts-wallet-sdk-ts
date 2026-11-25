/**
 * did:key / did:jwk がキャッシュ層を必要としないことの確認。
 *
 * did:key / did:jwk は DID 文字列から決定的に解決でき、キャッシュを必要としない。
 * 決定的とは「解決が入力 DID 文字列だけで完結し、ネットワーク I/O が無い」という意味であり、
 * キャッシュしても削減できるコストが無い（むしろ失効反映を遅らせる余地を増やすだけ）。
 *
 * ここでは「呼ばれたら失敗する fetch」を `globalThis.fetch` に差し込み、解決がネットワークに
 * 一切触れないことを実挙動で固定する。did:web と違ってキャッシュ層を追加しない根拠を、
 * 文章ではなく回帰テストとして残す。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { createDidJwk, MethodJwk, resolveDidJwk } from '../jwk/method-jwk.js';
import { createDidKey, MethodKey, resolveDidKey } from '../method-key.js';

const originalFetch = globalThis.fetch;

/** 呼ばれた回数を記録し、必ず例外を投げる fetch を仕込む。 */
function forbidFetch(): { calls: () => number } {
  let calls = 0;
  globalThis.fetch = (() => {
    calls += 1;
    throw new Error('network access is not allowed for deterministic DID methods');
  }) as unknown as typeof fetch;
  return { calls: () => calls };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** did:key 用の決定的な Ed25519 公開鍵（値そのものに意味はない）。 */
const ED25519_PUBLIC_KEY = new Uint8Array(32).fill(7);

describe('did:key は解決にネットワークを使わない（キャッシュ不要）', () => {
  it('resolveDidKey はグローバル fetch を呼ばない', async () => {
    const did = createDidKey('Ed25519', ED25519_PUBLIC_KEY).id;
    const spy = forbidFetch();

    const doc = resolveDidKey(did);

    expect(doc.id).toBe(did);
    expect(spy.calls()).toBe(0);
  });

  it('MethodKey.resolve もネットワークに出ず、同じ入力に同じ結果を返す（決定的）', async () => {
    const did = createDidKey('Ed25519', ED25519_PUBLIC_KEY).id;
    const spy = forbidFetch();

    const first = await new MethodKey().resolve(did);
    const second = await new MethodKey().resolve(did);

    expect(spy.calls()).toBe(0);
    expect(second).toEqual(first);
  });
});

describe('did:jwk は解決にネットワークを使わない（キャッシュ不要）', () => {
  it('resolveDidJwk はグローバル fetch を呼ばない', () => {
    const did = createDidJwk({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    }).id;
    const spy = forbidFetch();

    const doc = resolveDidJwk(did);

    expect(doc.id).toBe(did);
    expect(spy.calls()).toBe(0);
  });

  it('MethodJwk.resolve もネットワークに出ず、同じ入力に同じ結果を返す（決定的）', async () => {
    const did = createDidJwk({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    }).id;
    const spy = forbidFetch();

    const first = await new MethodJwk().resolve(did);
    const second = await new MethodJwk().resolve(did);

    expect(spy.calls()).toBe(0);
    expect(second).toEqual(first);
  });
});
