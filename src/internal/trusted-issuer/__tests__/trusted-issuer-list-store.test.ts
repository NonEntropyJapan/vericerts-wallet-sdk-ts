/**
 * TrustedIssuerListStoreの振る舞い検証。
 *
 * MemoryStorage を注入し、リスト作成・取得・一覧・エントリ upsert/削除・削除・破損データの
 * 復号エラー・`isTrustedIssuer` の有効期限/対応 VC 種別判定を確認する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { isTrustedIssuer, TrustedIssuerListStore } from '../trusted-issuer-list-store.js';
import type { TrustedIssuerEntry, TrustedIssuerList } from '../types.js';

function fixedClock(start = '2026-01-01T00:00:00.000Z'): () => Date {
  return () => new Date(start);
}

function fixedIdGen(...ids: string[]): () => string {
  let i = 0;
  return () => ids[i++] ?? `id-${i}`;
}

function newStore(now = fixedClock(), idGen = fixedIdGen('list-1')): TrustedIssuerListStore {
  return new TrustedIssuerListStore(new MemoryStorage(), now, idGen);
}

describe('TrustedIssuerListStore.createList', () => {
  it('仕様通りの固定フィールド（type/version）と採番した id・issuedAt でリストを作成する', async () => {
    const store = newStore();
    const list = await store.createList({
      listOperator: 'did:example:operator',
      listName: 'My TIL',
    });
    expect(list.id).toBe('list-1');
    expect(list.type).toBe('TrustedIssuerList');
    expect(list.version).toBe('TSLv1');
    expect(list.listOperator).toBe('did:example:operator');
    expect(list.listName).toBe('My TIL');
    expect(list.issuedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(list.trustedIssuers).toEqual([]);
  });

  it('sourceUrl / intervalMs / nextUpdate / 初期 trustedIssuers を保持する', async () => {
    const store = newStore();
    const entry: TrustedIssuerEntry = { id: 'did:example:issuer1', name: 'Issuer 1' };
    const list = await store.createList({
      listOperator: 'did:example:operator',
      listName: 'Subscribed TIL',
      sourceUrl: 'https://example.com/til.json',
      intervalMs: 86_400_000,
      nextUpdate: '2026-02-01T00:00:00.000Z',
      trustedIssuers: [entry],
    });
    expect(list.sourceUrl).toBe('https://example.com/til.json');
    expect(list.intervalMs).toBe(86_400_000);
    expect(list.nextUpdate).toBe('2026-02-01T00:00:00.000Z');
    expect(list.trustedIssuers).toEqual([entry]);
  });
});

describe('TrustedIssuerListStore.getList / listLists', () => {
  it('未存在の id は null を返す', async () => {
    const store = newStore();
    expect(await store.getList('missing')).toBeNull();
  });

  it('作成済みリストを全件返す', async () => {
    const store = newStore(fixedClock(), fixedIdGen('list-1', 'list-2'));
    await store.createList({ listOperator: 'did:example:op1', listName: 'A' });
    await store.createList({ listOperator: 'did:example:op2', listName: 'B' });
    const lists = await store.listLists();
    expect(lists.map((l) => l.id).sort()).toEqual(['list-1', 'list-2']);
  });
});

describe('TrustedIssuerListStore.addEntry / removeEntry', () => {
  it('対象リストへ発行者エントリを追加する', async () => {
    const store = newStore();
    const list = await store.createList({ listOperator: 'did:example:operator', listName: 'TIL' });
    const updated = await store.addEntry(list.id, { id: 'did:example:issuer1', name: 'Issuer 1' });
    expect(updated?.trustedIssuers).toEqual([{ id: 'did:example:issuer1', name: 'Issuer 1' }]);
  });

  it('同じ id のエントリを追加すると upsert（上書き）する', async () => {
    const store = newStore();
    const list = await store.createList({ listOperator: 'did:example:operator', listName: 'TIL' });
    await store.addEntry(list.id, { id: 'did:example:issuer1', name: 'Old Name' });
    const updated = await store.addEntry(list.id, { id: 'did:example:issuer1', name: 'New Name' });
    expect(updated?.trustedIssuers).toEqual([{ id: 'did:example:issuer1', name: 'New Name' }]);
  });

  it('未存在のリストへの追加は null を返す no-op', async () => {
    const store = newStore();
    const result = await store.addEntry('missing', { id: 'did:example:issuer1', name: 'Issuer 1' });
    expect(result).toBeNull();
  });

  it('発行者エントリを削除する', async () => {
    const store = newStore();
    const list = await store.createList({ listOperator: 'did:example:operator', listName: 'TIL' });
    await store.addEntry(list.id, { id: 'did:example:issuer1', name: 'Issuer 1' });
    const updated = await store.removeEntry(list.id, 'did:example:issuer1');
    expect(updated?.trustedIssuers).toEqual([]);
  });

  it('未存在のエントリの削除は no-op（リストはそのまま返る）', async () => {
    const store = newStore();
    const list = await store.createList({ listOperator: 'did:example:operator', listName: 'TIL' });
    const updated = await store.removeEntry(list.id, 'did:example:unknown');
    expect(updated?.trustedIssuers).toEqual([]);
  });
});

describe('TrustedIssuerListStore.deleteList', () => {
  it('リストを削除する（削除後は getList が null）', async () => {
    const store = newStore();
    const list = await store.createList({ listOperator: 'did:example:operator', listName: 'TIL' });
    await store.deleteList(list.id);
    expect(await store.getList(list.id)).toBeNull();
  });

  it('未存在の id の削除は no-op', async () => {
    const store = newStore();
    await expect(store.deleteList('missing')).resolves.toBeUndefined();
  });
});

describe('TrustedIssuerListStore 破損データ', () => {
  it('storage 上の非 JSON データは STORAGE_RECORD_CORRUPTED（6005）を投げる', async () => {
    const storage = new MemoryStorage();
    await storage.set('trusted-issuer-list/corrupt', new TextEncoder().encode('not json'));
    const store = new TrustedIssuerListStore(storage);
    await expect(store.getList('corrupt')).rejects.toThrow(VericertsError);
    try {
      await store.getList('corrupt');
      throw new Error('unreachable');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.STORAGE_RECORD_CORRUPTED);
    }
  });
});

describe('isTrustedIssuer', () => {
  const baseList: TrustedIssuerList = {
    id: 'list-1',
    type: 'TrustedIssuerList',
    version: 'TSLv1',
    listOperator: 'did:example:operator',
    listName: 'TIL',
    issuedAt: '2026-01-01T00:00:00.000Z',
    trustedIssuers: [
      { id: 'did:example:issuer1', name: 'Issuer 1', credentialTypes: ['DiplomaCredential'] },
      {
        id: 'did:example:issuer2',
        name: 'Issuer 2',
        validFrom: '2026-01-01T00:00:00.000Z',
        validUntil: '2026-12-31T23:59:59.000Z',
      },
    ],
  };

  it('id が一致すれば true（credentialType 未指定は無条件一致）', () => {
    expect(isTrustedIssuer(baseList, 'did:example:issuer1')).toBe(true);
  });

  it('未登録の DID は false', () => {
    expect(isTrustedIssuer(baseList, 'did:example:unknown')).toBe(false);
  });

  it('credentialTypes に含まれない種別を指定すると false', () => {
    expect(
      isTrustedIssuer(baseList, 'did:example:issuer1', { credentialType: 'OtherCredential' }),
    ).toBe(false);
  });

  it('credentialTypes に含まれる種別を指定すると true', () => {
    expect(
      isTrustedIssuer(baseList, 'did:example:issuer1', { credentialType: 'DiplomaCredential' }),
    ).toBe(true);
  });

  it('validFrom/validUntil の範囲外の基準時刻では false', () => {
    expect(
      isTrustedIssuer(baseList, 'did:example:issuer2', {
        at: new Date('2025-01-01T00:00:00.000Z'),
      }),
    ).toBe(false);
    expect(
      isTrustedIssuer(baseList, 'did:example:issuer2', {
        at: new Date('2027-01-01T00:00:00.000Z'),
      }),
    ).toBe(false);
  });

  it('validFrom/validUntil の範囲内の基準時刻では true', () => {
    expect(
      isTrustedIssuer(baseList, 'did:example:issuer2', {
        at: new Date('2026-06-01T00:00:00.000Z'),
      }),
    ).toBe(true);
  });

  it('解釈不能な validUntil / validFrom を持つエントリは信頼しない（fail-closed）', () => {
    const list: TrustedIssuerList = {
      ...baseList,
      trustedIssuers: [
        { id: 'did:example:bad-until', name: 'a', validUntil: 'not-a-date' },
        { id: 'did:example:bad-from', name: 'a', validFrom: '2999-13-45' },
        { id: 'did:example:empty-until', name: 'a', validUntil: '' },
      ],
    };
    expect(isTrustedIssuer(list, 'did:example:bad-until')).toBe(false);
    expect(isTrustedIssuer(list, 'did:example:bad-from')).toBe(false);
    expect(isTrustedIssuer(list, 'did:example:empty-until')).toBe(false);
  });

  it('基準時刻 at が Invalid Date の場合は false（fail-closed）', () => {
    expect(isTrustedIssuer(baseList, 'did:example:issuer1', { at: new Date('nope') })).toBe(false);
  });
});
