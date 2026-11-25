/**
 * 解釈できない有効期間を持つ発行者エントリの入口検査。
 *
 * `isWithinValidity` は解釈できない期間を fail-closed で「不一致」とするため、受理して保存すると
 * そのエントリは何のエラーも警告も出ないまま一生信頼されない。登録したつもりの発行者の VC が
 * 黙って未検証扱いになる。入口（`createList` / `addEntry`）で拒否して呼び出し側に知らせる。
 *
 * `validFrom` / `validUntil` はオフセット付きの厳格な ISO 8601 形式を要求する。
 */

import { describe, expect, it } from 'bun:test';
import { MemoryStorage } from '../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { TrustedIssuerListStore } from '../trusted-issuer-list-store.js';

const newStore = () =>
  new TrustedIssuerListStore(
    new MemoryStorage(),
    () => new Date('2026-01-01T00:00:00.000Z'),
    () => 'list-1',
  );

const LIST = { listOperator: 'op', listName: 'l' };

/** 受理されない期間の値。日付のみ・オフセット無しの日時・非 ISO・暦として不正。 */
const UNPARSABLE = ['2026-12-31', '2026-12-31T00:00:00', 'not-a-date', '', '2026-02-30T00:00:00Z'];

async function rejection(promise: Promise<unknown>): Promise<VericertsError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof VericertsError) return err;
    throw err;
  }
  throw new Error('should have thrown');
}

describe('解釈できない有効期間のエントリは入口で拒否する', () => {
  it.each(UNPARSABLE)('addEntry は validUntil %p を拒否する', async (validUntil) => {
    const store = newStore();
    await store.createList(LIST);

    const err = await rejection(
      store.addEntry('list-1', { id: 'did:example:a', name: 'a', validUntil }),
    );

    expect(err.code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
    expect(err.context).toMatchObject({
      reason: 'trusted_issuer_validity_unparsable',
      field: 'validUntil',
    });
  });

  it.each(UNPARSABLE)('addEntry は validFrom %p を拒否する', async (validFrom) => {
    const store = newStore();
    await store.createList(LIST);

    const err = await rejection(
      store.addEntry('list-1', { id: 'did:example:a', name: 'a', validFrom }),
    );

    expect(err.context).toMatchObject({ field: 'validFrom' });
  });

  it('createList の初期エントリも拒否する', async () => {
    const store = newStore();

    const err = await rejection(
      store.createList({
        ...LIST,
        trustedIssuers: [{ id: 'did:example:a', name: 'a', validUntil: '2026-12-31' }],
      }),
    );

    expect(err.code).toBe(ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('拒否したエントリは保存されない（部分適用しない）', async () => {
    const store = newStore();
    await store.createList(LIST);

    await rejection(
      store.addEntry('list-1', { id: 'did:example:a', name: 'a', validUntil: '2026-12-31' }),
    );

    expect((await store.getList('list-1'))?.trustedIssuers).toEqual([]);
  });

  it('オフセット付きの日時と、期間を持たないエントリは受理する', async () => {
    const store = newStore();
    await store.createList(LIST);

    await store.addEntry('list-1', {
      id: 'did:example:ok',
      name: 'a',
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2026-12-31T23:59:59.000Z',
    });
    await store.addEntry('list-1', { id: 'did:example:forever', name: 'b' });

    expect((await store.getList('list-1'))?.trustedIssuers).toHaveLength(2);
  });
});
