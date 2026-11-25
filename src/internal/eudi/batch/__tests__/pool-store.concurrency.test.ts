/**
 * BatchCredentialPoolStore の並行更新。
 *
 * `recordConsumption` / `recordRefill` は get → 加算 → set の read-modify-write であり、直列化しないと
 * 並行呼び出しが同じ旧値を読んで上書きし合い（lost update）、使用済み数が過少計上される。
 */

import { describe, expect, test } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { BatchCredentialPoolStore } from '../pool-store.js';

async function newPool(): Promise<{ store: BatchCredentialPoolStore; id: string }> {
  const store = new BatchCredentialPoolStore(new MemoryStorage(), () => 1_700_000_000_000);
  const pool = await store.create({
    vct: 'urn:eudi:pid:1',
    issuerDID: 'did:example:issuer',
    totalCount: 10,
    threshold: 3,
  });
  return { store, id: pool.id };
}

describe('BatchCredentialPoolStore の並行更新', () => {
  test('並行する recordConsumption が全件 usedCount に反映される', async () => {
    const { store, id } = await newPool();
    await Promise.all([
      store.recordConsumption(id),
      store.recordConsumption(id),
      store.recordConsumption(id, 2),
    ]);
    expect((await store.get(id))?.usedCount).toBe(4);
  });

  test('並行する recordRefill が全件 totalCount に反映される', async () => {
    const { store, id } = await newPool();
    await Promise.all([store.recordRefill(id, 5), store.recordRefill(id, 7)]);
    expect((await store.get(id))?.totalCount).toBe(22);
  });

  test('総数を超える並行消費は超過分だけ拒否され、残りは反映される', async () => {
    const { store, id } = await newPool();
    const results = await Promise.allSettled(
      Array.from({ length: 12 }, () => store.recordConsumption(id)),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(10);
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(2);
    expect((await store.get(id))?.usedCount).toBe(10);
  });
});
