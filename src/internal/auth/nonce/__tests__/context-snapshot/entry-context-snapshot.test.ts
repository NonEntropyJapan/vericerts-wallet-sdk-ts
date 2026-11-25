/**
 * `SeenNonceEntry.context` に載るのが**正規化スナップショット**であることの回帰テスト。
 *
 * replay ガードは入口で `NonceContext` を `Object.create(null)` 由来の複製へ畳み、以降は
 * その複製だけを下層 `NonceStore#checkAndUse` へ渡す。複製は**公開 DI seam** である
 * `NonceStoreAdapter.set` / `get` / `entries` と `onEvict(entry)` から観測できるため、
 * 後方非互換な観測可能挙動として仕様に記録されている。その契約をここで固定する。
 *
 * 契約は 4 つ:
 * 1. 参照同一性は保たれない（元オブジェクトは載らない）
 * 2. `Object.prototype` を継承しない（`hasOwnProperty` / `instanceof Object` が使えない）
 * 3. own の文字列キー・値・列挙可能性は変わらない（アクセサはデータプロパティへ畳まれる）
 * 4. ガードを介さない直接呼び出しは正規化されない（呼び出し側のオブジェクトがそのまま載る）
 */

import { describe, expect, it } from 'bun:test';
import { snapshotNonceContext } from '../../context-snapshot.js';
import { createNonceStore } from '../../store.js';
import type { NonceContext, NonceStoreAdapter, SeenNonceEntry } from '../../types.js';

const NONCE = 'AQIDBAUGBwgJCgsMDQ4PEA';
const VERIFIER = 'https://verifier.example/client';
const NOW = 1_700_000_000_000;

/** `set` に渡った `SeenNonceEntry` を記録するだけのアダプタ（公開 DI seam の観測点）。 */
function spyAdapter(): {
  readonly adapter: NonceStoreAdapter;
  readonly seen: () => readonly SeenNonceEntry[];
} {
  const store = new Map<string, SeenNonceEntry>();
  const observed: SeenNonceEntry[] = [];
  const adapter: NonceStoreAdapter = {
    get: (key) => Promise.resolve(store.get(key)),
    set: (key, entry) => {
      observed.push(entry);
      store.set(key, entry);
      return Promise.resolve();
    },
    delete: (key) => {
      store.delete(key);
      return Promise.resolve();
    },
    entries: () => Promise.resolve([...store.entries()]),
  };
  return { adapter, seen: () => observed };
}

/** spy アダプタを差した `NonceStore` を作る。 */
function makeStore(adapter: NonceStoreAdapter) {
  return createNonceStore({ backend: 'redis', adapter, now: () => NOW });
}

describe('SeenNonceEntry.context はスナップショット', () => {
  it('ガードが畳んだスナップショットを渡すと参照同一でなくプロトタイプを持たない', async () => {
    const original: NonceContext = { flow: 'oid4vp', clientId: VERIFIER };
    const snapshot = snapshotNonceContext(original);
    const { adapter, seen } = spyAdapter();

    await makeStore(adapter).checkAndUse(NONCE, snapshot);

    const entry = seen()[0];
    expect(entry).toBeDefined();
    // 1. 参照同一性は保たれない
    expect(entry?.context).not.toBe(original);
    // 2. Object.prototype を継承しない
    expect(Object.getPrototypeOf(entry?.context as object)).toBeNull();
    expect(entry?.context instanceof Object).toBe(false);
    // 3. own の文字列キーと値は変わらない
    expect(Object.hasOwn(entry?.context as object, 'clientId')).toBe(true);
    expect(entry?.context.flow).toBe('oid4vp');
    expect(JSON.stringify(entry?.context)).toBe(JSON.stringify(original));
  });

  it('own のアクセサはデータプロパティへ畳まれ、列挙可能性は引き継ぐ', () => {
    const ctx = { flow: 'oid4vp' } as unknown as NonceContext;
    let reads = 0;
    Object.defineProperty(ctx, 'clientId', {
      get(): string {
        reads += 1;
        return VERIFIER;
      },
      enumerable: true,
      configurable: true,
    });
    // 非列挙の own 文字列キーも写すが、列挙可能性は元のまま保つ。
    Object.defineProperty(ctx, 'issuer', {
      value: 'https://issuer.example',
      enumerable: false,
      configurable: true,
      writable: true,
    });

    const snapshot = snapshotNonceContext(ctx);

    expect(reads).toBe(1);
    const clientId = Object.getOwnPropertyDescriptor(snapshot, 'clientId');
    expect(clientId?.get).toBeUndefined();
    expect(clientId?.value).toBe(VERIFIER);
    expect(clientId?.enumerable).toBe(true);
    expect(Object.getOwnPropertyDescriptor(snapshot, 'issuer')?.enumerable).toBe(false);
    // 何度読んでも同じ値（アクセサは入口で 1 度だけ評価済み）。
    const read = (): unknown => (snapshot as unknown as Record<string, unknown>).clientId;
    expect(read()).toBe(read());
    expect(reads).toBe(1);
  });

  it('ガードを介さない直接呼び出しは正規化されず呼び出し側のオブジェクトが載る', async () => {
    const original: NonceContext = { flow: 'oid4vp', clientId: VERIFIER };
    const { adapter, seen } = spyAdapter();

    await makeStore(adapter).checkAndUse(NONCE, original);

    expect(seen()[0]?.context).toBe(original);
  });
});
