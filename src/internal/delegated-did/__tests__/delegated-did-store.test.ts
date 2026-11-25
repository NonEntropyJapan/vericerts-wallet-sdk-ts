/**
 * DelegatedDIDStoreの振る舞い検証。
 *
 * MemoryStorage を注入し、upsert（作成/更新）・取得・controllerDID 絞り込み一覧・ステータス更新・
 * 削除・破損データの復号エラーを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { DelegatedDIDStore } from '../delegated-did-store.js';

function fixedClock(start = '2026-01-01T00:00:00.000Z'): () => Date {
  return () => new Date(start);
}

function newStore(now = fixedClock()): DelegatedDIDStore {
  return new DelegatedDIDStore(new MemoryStorage(), now);
}

describe('DelegatedDIDStore.upsert', () => {
  it('status/resolvedAt 省略時は既定値（unknown / now）で作成する', async () => {
    const store = newStore();
    const record = await store.upsert({
      did: 'did:example:delegate1',
      controllerDID: 'did:example:controller',
      name: '株式会社○○',
    });
    expect(record).toEqual({
      did: 'did:example:delegate1',
      controllerDID: 'did:example:controller',
      name: '株式会社○○',
      status: 'unknown',
      resolvedAt: '2026-01-01T00:00:00.000Z',
    });
  });

  it('status/resolvedAt を明示指定すると採用する', async () => {
    const store = newStore();
    const record = await store.upsert({
      did: 'did:example:delegate1',
      controllerDID: 'did:example:controller',
      name: '株式会社○○',
      status: 'active',
      resolvedAt: '2025-06-01T00:00:00.000Z',
    });
    expect(record.status).toBe('active');
    expect(record.resolvedAt).toBe('2025-06-01T00:00:00.000Z');
  });

  it('同じ did を再度 upsert すると上書きする', async () => {
    const store = newStore();
    await store.upsert({
      did: 'did:example:delegate1',
      controllerDID: 'did:example:controller',
      name: 'Old Name',
    });
    const updated = await store.upsert({
      did: 'did:example:delegate1',
      controllerDID: 'did:example:controller',
      name: 'New Name',
    });
    expect(updated.name).toBe('New Name');
    const stored = await store.get('did:example:delegate1');
    expect(stored?.name).toBe('New Name');
  });
});

describe('DelegatedDIDStore.get / list', () => {
  it('未存在の did は null を返す', async () => {
    const store = newStore();
    expect(await store.get('missing')).toBeNull();
  });

  it('controllerDID 未指定時は全件を返す', async () => {
    const store = newStore();
    await store.upsert({ did: 'did:example:d1', controllerDID: 'did:example:c1', name: 'A' });
    await store.upsert({ did: 'did:example:d2', controllerDID: 'did:example:c2', name: 'B' });
    const all = await store.list();
    expect(all.map((r) => r.did).sort()).toEqual(['did:example:d1', 'did:example:d2']);
  });

  it('controllerDID 指定時はその controller のレコードのみ返す', async () => {
    const store = newStore();
    await store.upsert({ did: 'did:example:d1', controllerDID: 'did:example:c1', name: 'A' });
    await store.upsert({ did: 'did:example:d2', controllerDID: 'did:example:c2', name: 'B' });
    const filtered = await store.list('did:example:c1');
    expect(filtered.map((r) => r.did)).toEqual(['did:example:d1']);
  });
});

describe('DelegatedDIDStore.updateStatus', () => {
  it('ステータスと resolvedAt を更新する', async () => {
    let now = '2026-01-01T00:00:00.000Z';
    const store = new DelegatedDIDStore(new MemoryStorage(), () => new Date(now));
    await store.upsert({
      did: 'did:example:delegate1',
      controllerDID: 'did:example:controller',
      name: 'A',
      status: 'unknown',
      resolvedAt: '2025-01-01T00:00:00.000Z',
    });
    now = '2026-06-01T00:00:00.000Z';
    const updated = await store.updateStatus('did:example:delegate1', 'revoked');
    expect(updated).toEqual({
      did: 'did:example:delegate1',
      controllerDID: 'did:example:controller',
      name: 'A',
      status: 'revoked',
      resolvedAt: '2026-06-01T00:00:00.000Z',
    });
  });

  it('未存在の did は null を返す no-op', async () => {
    const store = newStore();
    expect(await store.updateStatus('missing', 'active')).toBeNull();
  });
});

describe('DelegatedDIDStore.remove', () => {
  it('レコードを削除する（削除後は get が null）', async () => {
    const store = newStore();
    await store.upsert({ did: 'did:example:d1', controllerDID: 'did:example:c1', name: 'A' });
    await store.remove('did:example:d1');
    expect(await store.get('did:example:d1')).toBeNull();
  });

  it('未存在の did の削除は no-op', async () => {
    const store = newStore();
    await expect(store.remove('missing')).resolves.toBeUndefined();
  });
});

describe('DelegatedDIDStore 破損データ', () => {
  it('storage 上の非 JSON データは STORAGE_RECORD_CORRUPTED（6005）を投げる', async () => {
    const storage = new MemoryStorage();
    await storage.set('delegated-did/corrupt', new TextEncoder().encode('not json'));
    const store = new DelegatedDIDStore(storage);
    try {
      await store.get('corrupt');
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.STORAGE_RECORD_CORRUPTED);
    }
  });

  it('status が不正な値の場合も STORAGE_RECORD_CORRUPTED（6005）を投げる', async () => {
    const storage = new MemoryStorage();
    await storage.set(
      'delegated-did/bad-status',
      new TextEncoder().encode(
        JSON.stringify({
          did: 'did:example:d1',
          controllerDID: 'did:example:c1',
          name: 'A',
          resolvedAt: '2026-01-01T00:00:00.000Z',
          status: 'not-a-status',
        }),
      ),
    );
    const store = new DelegatedDIDStore(storage);
    await expect(store.get('bad-status')).rejects.toThrow(VericertsError);
  });
});
