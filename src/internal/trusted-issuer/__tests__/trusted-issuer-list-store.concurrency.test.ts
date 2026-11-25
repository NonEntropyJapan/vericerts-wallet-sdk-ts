/**
 * TrustedIssuerListStore の並行更新。
 *
 * `addEntry` / `removeEntry` は get → 加工 → set の read-modify-write であり、直列化しないと並行呼び出しが
 * 同じ旧リストを読んで上書きし合う（追加の消失、取り消したはずの信頼エントリの復活 = fail-open）。
 * `BatchCredentialPoolStore` の `pool-store.concurrency.test.ts` と同形。
 */

import { describe, expect, test } from 'bun:test';
import { MemoryStorage, type Storage } from '../../../storage/storage.js';
import { TrustedIssuerListStore } from '../trusted-issuer-list-store.js';
import type { TrustedIssuerEntry } from '../types.js';

const entry = (id: string): TrustedIssuerEntry => ({ id, name: id });

/** `get` の後に 1 ティック譲り、並行呼び出しが同じ旧値を読む窓を確実に開く storage。 */
class YieldingStorage extends MemoryStorage {
  override async get(key: string): Promise<Uint8Array | null> {
    const value = await super.get(key);
    await new Promise((resolve) => setTimeout(resolve, 1));
    return value;
  }
}

async function newList(
  storage: Storage = new YieldingStorage(),
): Promise<{ store: TrustedIssuerListStore; id: string }> {
  const store = new TrustedIssuerListStore(storage, () => new Date('2026-01-01T00:00:00.000Z'));
  const list = await store.createList({ listOperator: 'did:example:op', listName: 'til' });
  return { store, id: list.id };
}

const ids = async (store: TrustedIssuerListStore, id: string): Promise<string[]> =>
  ((await store.getList(id))?.trustedIssuers ?? []).map((e) => e.id).sort();

describe('TrustedIssuerListStore の並行更新', () => {
  test('並行する addEntry が全件残る', async () => {
    const { store, id } = await newList();
    await Promise.all([
      store.addEntry(id, entry('did:example:a')),
      store.addEntry(id, entry('did:example:b')),
      store.addEntry(id, entry('did:example:c')),
    ]);
    expect(await ids(store, id)).toEqual(['did:example:a', 'did:example:b', 'did:example:c']);
  });

  test('removeEntry と addEntry の競合で、削除した信頼エントリが復活しない', async () => {
    const { store, id } = await newList();
    await store.addEntry(id, entry('did:example:x'));
    await Promise.all([
      store.addEntry(id, entry('did:example:a')),
      store.removeEntry(id, 'did:example:x'),
    ]);
    expect(await ids(store, id)).toEqual(['did:example:a']);
  });

  test('並行する removeEntry が互いの削除を取り消さない', async () => {
    const { store, id } = await newList();
    for (const did of ['x', 'y', 'z']) await store.addEntry(id, entry(`did:example:${did}`));
    await Promise.all([
      store.removeEntry(id, 'did:example:x'),
      store.removeEntry(id, 'did:example:y'),
    ]);
    expect(await ids(store, id)).toEqual(['did:example:z']);
  });

  test('別リストへの更新は互いをブロックしない', async () => {
    const storage = new YieldingStorage();
    const { store, id } = await newList(storage);
    const other = await store.createList({
      id: 'other',
      listOperator: 'did:example:op',
      listName: 'o',
    });
    await Promise.all([
      store.addEntry(id, entry('did:example:a')),
      store.addEntry(other.id, entry('did:example:b')),
    ]);
    expect(await ids(store, id)).toEqual(['did:example:a']);
    expect(await ids(store, other.id)).toEqual(['did:example:b']);
  });
});
