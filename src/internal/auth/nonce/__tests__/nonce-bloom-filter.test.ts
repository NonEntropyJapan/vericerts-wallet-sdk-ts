/**
 * 高負荷時プリフィルタ（Bloom Filter）のユニットテスト。
 *
 * 検証内容:
 * - `bloomFilter` 未設定（既定）では従来どおり毎回 `adapter.get` へ問い合わせる（後方互換）。
 * - `bloomFilter: true` を有効化すると、初見（未追加）のキーは `adapter.get` を経由せず判定できる
 *   （＝プリフィルタとして機能している）。
 * - 既に追加したキーは必ず `adapter.get` で確定判定される（偽陰性が起きていないことの確認）。
 * - `capacity` を超えてレイヤーが増えても（Scalable Bloom Filter）、既存キー全件が引き続き
 *   「追加されたかもしれない」と判定され、リプレイ検知が抜けない。
 * - `falsePositiveRate` が `(0, 1)` の範囲外なら `createNonceStore` が `RangeError` を投げる。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { bitPosition } from '../bloom-filter.js';
import { MemoryNonceStoreAdapter } from '../memory-adapter.js';
import { createNonceStore } from '../store.js';
import type { NonceContext, NonceStoreAdapter, SeenNonceEntry } from '../types.js';

const CTX: NonceContext = { flow: 'oid4vp', clientId: 'https://verifier.example/client' };
const TTL_MS = 60_000;

/** `adapter.get` / `adapter.set` の呼び出し回数を数える計装アダプタ。 */
class CountingAdapter implements NonceStoreAdapter {
  readonly #inner = new MemoryNonceStoreAdapter();
  getCalls = 0;
  setCalls = 0;

  get(key: string): Promise<SeenNonceEntry | undefined> {
    this.getCalls += 1;
    return this.#inner.get(key);
  }
  set(key: string, entry: SeenNonceEntry): Promise<void> {
    this.setCalls += 1;
    return this.#inner.set(key, entry);
  }
  delete(key: string): Promise<void> {
    return this.#inner.delete(key);
  }
  entries(): Promise<readonly (readonly [string, SeenNonceEntry])[]> {
    return this.#inner.entries();
  }
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

describe('NonceStore: 高負荷時プリフィルタ（Bloom Filter）', () => {
  it('既定（未設定）では初見の nonce でも adapter.get を毎回呼ぶ', async () => {
    const adapter = new CountingAdapter();
    const store = createNonceStore({ backend: 'memory', adapter });

    const seen = await store.has(store.generate(), CTX);

    expect(seen).toBe(false);
    expect(adapter.getCalls).toBe(1);
  });

  it('bloomFilter: true — 初見の nonce は adapter.get を経由せず「未消費」と判定する', async () => {
    const adapter = new CountingAdapter();
    const store = createNonceStore({ backend: 'memory', adapter, bloomFilter: true });

    const seen = await store.has(store.generate(), CTX);

    expect(seen).toBe(false);
    expect(adapter.getCalls).toBe(0);
  });

  it('bloomFilter: true — checkAndUse も初見 nonce は adapter.get を経由せず消費記録する', async () => {
    const adapter = new CountingAdapter();
    const store = createNonceStore({ backend: 'memory', adapter, bloomFilter: true });
    const nonce = store.generate();

    await store.checkAndUse(nonce, CTX, { ttlMs: TTL_MS });

    expect(adapter.getCalls).toBe(0);
    expect(adapter.setCalls).toBe(1);
    // 追加後は adapter.get 経由の確定判定に切り替わり、消費済みと判定できる（偽陰性なし）。
    expect(await store.has(nonce, CTX)).toBe(true);
    expect(adapter.getCalls).toBe(1);
  });

  it('bloomFilter: true でも追加済みキーの再消費は adapter.get で確定判定され 4010 になる（偽陰性なし）', async () => {
    const adapter = new CountingAdapter();
    const store = createNonceStore({ backend: 'memory', adapter, bloomFilter: true });
    const nonce = store.generate();

    await store.checkAndUse(nonce, CTX, { ttlMs: TTL_MS });
    const getCallsAfterFirstUse = adapter.getCalls;

    await expectCode(
      () => store.checkAndUse(nonce, CTX, { ttlMs: TTL_MS }),
      ErrorCodes.REPLAY_DETECTED,
    );

    // 2 回目はプリフィルタが「追加されたかもしれない」と判定し、必ず adapter.get で確定判定する。
    expect(adapter.getCalls).toBeGreaterThan(getCallsAfterFirstUse);
  });

  it('容量超過でレイヤーが増えても、既存キー全件がリプレイとして検知され続ける', async () => {
    const adapter = new CountingAdapter();
    // 容量 2 の極小フィルタで、10 件の追加により複数回のレイヤー拡張を強制する。
    const store = createNonceStore({
      backend: 'memory',
      adapter,
      bloomFilter: { capacity: 2 },
    });
    const nonces = Array.from({ length: 10 }, () => store.generate());

    for (const nonce of nonces) {
      await store.put(nonce, CTX, TTL_MS);
    }

    // 未失効のまま再 put すると、レイヤーがいくつ増えていても全件 4010 になるはず
    // （どれか 1 件でも偽陰性化すると「初見」扱いで上書きされ、例外が飛ばない）。
    for (const nonce of nonces) {
      await expectCode(() => store.put(nonce, CTX, TTL_MS), ErrorCodes.REPLAY_DETECTED);
    }
  });

  it('falsePositiveRate が (0, 1) の範囲外だと createNonceStore が RangeError を投げる', () => {
    expect(() =>
      createNonceStore({ backend: 'memory', bloomFilter: { falsePositiveRate: 0 } }),
    ).toThrow(RangeError);
    expect(() =>
      createNonceStore({ backend: 'memory', bloomFilter: { falsePositiveRate: 1 } }),
    ).toThrow(RangeError);
    expect(() =>
      createNonceStore({ backend: 'memory', bloomFilter: { falsePositiveRate: -0.1 } }),
    ).toThrow(RangeError);
  });

  it('再起動後（永続アダプタに消費済みキーがある新インスタンス）でも消費済み nonce は 4010', async () => {
    const adapter = new CountingAdapter();
    const before = createNonceStore({ backend: 'memory', adapter, bloomFilter: true });
    const nonce = before.generate();
    await before.checkAndUse(nonce, CTX, { ttlMs: TTL_MS });

    // プロセス再起動相当: フィルタは空から始まるが、アダプタ（永続ストア）には消費記録が残っている。
    const after = createNonceStore({ backend: 'memory', adapter, bloomFilter: true });

    expect(await after.has(nonce, CTX)).toBe(true);
    await expectCode(
      () => after.checkAndUse(nonce, CTX, { ttlMs: TTL_MS }),
      ErrorCodes.REPLAY_DETECTED,
    );
  });

  it('復元後も初見の nonce は adapter.get を経由せずに判定される', async () => {
    const adapter = new CountingAdapter();
    const before = createNonceStore({ backend: 'memory', adapter, bloomFilter: true });
    await before.checkAndUse(before.generate(), CTX, { ttlMs: TTL_MS });
    const getCallsBefore = adapter.getCalls;

    const after = createNonceStore({ backend: 'memory', adapter, bloomFilter: true });

    expect(await after.has(after.generate(), CTX)).toBe(false);
    expect(adapter.getCalls).toBe(getCallsBefore);
  });
});

// `#setBit` / `#getBit`（bloom-filter.ts）が `index >> 3` / `index & 7` という int32
// ビット演算でバイト位置を求めていた。単一レイヤーの capacity が拡張を重ねて非常に大きくなり
// bitCount（ひいては index）が 2^31 を超えると、`index >> 3` が符号反転して負のバイト位置になる。
// `Uint8Array` は負の index への代入をサイレントに無視するため setBit が no-op になり、getBit は
// 常に false を返す。結果として mightContain が既知の nonce を「未知」と誤判定し、
// replay 検知の前段フィルタが偽陰性を返す。剰余演算
// （`Math.floor` / `%`）で求めることで回避している（バイト配列自体は実際には確保しない単体テスト）。
describe('bitPosition: 2^31 以上の index でも符号反転せず正しいバイト/ビット位置を返す', () => {
  it('2^31 を超える index でバイト位置が負にならない', () => {
    const bigIndex = 2 ** 31 + 5;

    // 旧実装（`index >> 3` / `index & 7`）はここで負のバイト位置に符号反転していた。
    expect(bigIndex >> 3).toBeLessThan(0);

    const [byteIndex, bitOffset] = bitPosition(bigIndex);
    expect(byteIndex).toBe(Math.floor(bigIndex / 8));
    expect(byteIndex).toBeGreaterThanOrEqual(0);
    expect(bitOffset).toBe(bigIndex % 8);
  });

  it('2^32 ちょうど・その周辺でも剰余演算どおりの位置を返す', () => {
    for (const index of [2 ** 32, 2 ** 32 + 7, 2 ** 32 - 1]) {
      const [byteIndex, bitOffset] = bitPosition(index);
      expect(byteIndex).toBe(Math.floor(index / 8));
      expect(bitOffset).toBe(index % 8);
    }
  });
});
