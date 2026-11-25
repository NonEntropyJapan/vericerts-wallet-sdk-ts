/**
 * `DelegatedDIDStore` の書き込み検査。
 *
 * 読み取り側（`decodeDelegatedDID`）が拒否する形のレコードを永続化すると、以後 `list()` が恒久的に
 * `6005` になる。永続化前に拒否し、正常レコードの一覧が壊れないことを確認する。
 * 任意引数（`status` / `resolvedAt`）は自身のプロパティに限って読む。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { DelegatedDIDStore } from '../delegated-did-store.js';

const base = {
  did: 'did:example:d1',
  controllerDID: 'did:example:c',
  name: '株式会社○○',
};

function newStore(): { store: DelegatedDIDStore; storage: MemoryStorage } {
  const storage = new MemoryStorage();
  return {
    store: new DelegatedDIDStore(storage, () => new Date('2026-01-01T00:00:00.000Z')),
    storage,
  };
}

async function codeOf(p: Promise<unknown>): Promise<string | null> {
  const e = await p.then(
    () => null,
    (err: unknown) => err,
  );
  return e instanceof VericertsError ? e.code : e === null ? null : 'non-vericerts';
}

describe('DelegatedDIDStore.upsert の入力検査', () => {
  it.each([
    ['status が列挙値外', { status: 'bogus' }, ErrorCodes.VC_SCHEMA_INVALID],
    ['status が非文字列', { status: 1 }, ErrorCodes.VC_SCHEMA_INVALID],
    ['name が非文字列', { name: 5 }, ErrorCodes.VC_SCHEMA_INVALID],
    ['resolvedAt が非文字列', { resolvedAt: 0 }, ErrorCodes.VC_SCHEMA_INVALID],
    ['did が非文字列', { did: 5 }, ErrorCodes.INVALID_DID],
    ['controllerDID が欠落', { controllerDID: undefined }, ErrorCodes.INVALID_DID],
  ])('%s は永続化前に拒否し、list() が壊れない', async (_name, override, code) => {
    const { store, storage } = newStore();
    await store.upsert({ ...base, did: 'did:example:ok' });
    expect(await codeOf(store.upsert({ ...base, ...override } as never))).toBe(code);
    expect(await storage.list('delegated-did/')).toEqual(['delegated-did/did:example:ok']);
    expect((await store.list()).map((r) => r.did)).toEqual(['did:example:ok']);
  });

  it('列挙値の status は受理して保存する', async () => {
    const { store } = newStore();
    for (const status of ['active', 'revoked', 'unknown'] as const) {
      expect((await store.upsert({ ...base, status })).status).toBe(status);
    }
  });
});

describe('DelegatedDIDStore.updateStatus の入力検査', () => {
  it('列挙値外の status は拒否し、保存済みレコードは変わらない', async () => {
    const { store } = newStore();
    await store.upsert({ ...base, status: 'active' });
    expect(await codeOf(store.updateStatus(base.did, 'bogus' as never))).toBe(
      ErrorCodes.VC_SCHEMA_INVALID,
    );
    expect((await store.get(base.did))?.status).toBe('active');
    expect(await store.list()).toHaveLength(1);
  });

  it('対象が未存在でも不正 status は null ではなく拒否する', async () => {
    const { store } = newStore();
    expect(await codeOf(store.updateStatus('did:example:none', 'bogus' as never))).toBe(
      ErrorCodes.VC_SCHEMA_INVALID,
    );
  });
});

describe('DelegatedDIDStore.upsert はプロトタイプ汚染を採用しない', () => {
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).status;
    delete (Object.prototype as Record<string, unknown>).resolvedAt;
  });

  it('Object.prototype.status / resolvedAt が汚染されていても既定値（unknown / now）になる', async () => {
    (Object.prototype as Record<string, unknown>).status = 'active';
    (Object.prototype as Record<string, unknown>).resolvedAt = '1999-01-01T00:00:00.000Z';
    const { store } = newStore();
    const record = await store.upsert(base);
    expect(record.status).toBe('unknown');
    expect(record.resolvedAt).toBe('2026-01-01T00:00:00.000Z');
    expect((await store.get(base.did))?.status).toBe('unknown');
  });
});
