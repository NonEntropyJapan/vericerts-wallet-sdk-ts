/**
 * BatchCredentialPoolStore（プール集約メタデータ）の振る舞い検証。
 *
 * MemoryStorage を注入し、作成（既定値）・取得・vct 絞り込み一覧・補充/消費の反映・削除・
 * 破損データの復号エラーを確認する。
 */

import { describe, expect, test } from 'bun:test';
import { MemoryStorage } from '../../../../storage/storage.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { BatchCredentialPoolStore } from '../pool-store.js';

const NOW = 1_700_000_000_000;

function fixedClock(start = NOW): () => number {
  return () => start;
}

function newStore(now = fixedClock(), idGen?: () => string): BatchCredentialPoolStore {
  const storage = new MemoryStorage();
  return idGen === undefined
    ? new BatchCredentialPoolStore(storage, now)
    : new BatchCredentialPoolStore(storage, now, idGen);
}

describe('BatchCredentialPoolStore.create', () => {
  test('usedCount 省略時は 0、createdAt/refreshedAt は作成時刻で初期化する', async () => {
    const store = newStore();
    const pool = await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      threshold: 3,
    });
    expect(pool).toEqual({
      id: pool.id,
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      usedCount: 0,
      threshold: 3,
      createdAt: NOW,
      refreshedAt: NOW,
    });
    expect(typeof pool.id).toBe('string');
    expect(pool.id.length).toBeGreaterThan(0);
  });

  test('usedCount を明示指定すると採用する', async () => {
    const store = newStore();
    const pool = await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      threshold: 3,
      usedCount: 4,
    });
    expect(pool.usedCount).toBe(4);
  });

  test('idGen で id 採番を注入できる', async () => {
    const store = newStore(fixedClock(), () => 'fixed-pool-id');
    const pool = await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      threshold: 3,
    });
    expect(pool.id).toBe('fixed-pool-id');
  });
});

describe('BatchCredentialPoolStore.get / list', () => {
  test('未存在の id は null を返す', async () => {
    const store = newStore();
    expect(await store.get('missing')).toBeNull();
  });

  test('vct 未指定時は全件を返す', async () => {
    const store = newStore();
    await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer1',
      totalCount: 10,
      threshold: 3,
    });
    await store.create({
      vct: 'urn:eudi:pid:2',
      issuerDID: 'did:example:issuer2',
      totalCount: 5,
      threshold: 2,
    });
    const all = await store.list();
    expect(all.map((p) => p.vct).sort()).toEqual(['urn:eudi:pid:1', 'urn:eudi:pid:2']);
  });

  test('vct 指定時はその VC Type のプールのみ返す', async () => {
    const store = newStore();
    await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer1',
      totalCount: 10,
      threshold: 3,
    });
    await store.create({
      vct: 'urn:eudi:pid:2',
      issuerDID: 'did:example:issuer2',
      totalCount: 5,
      threshold: 2,
    });
    const filtered = await store.list('urn:eudi:pid:1');
    expect(filtered.map((p) => p.vct)).toEqual(['urn:eudi:pid:1']);
  });
});

describe('BatchCredentialPoolStore.recordRefill', () => {
  test('totalCount を加算し refreshedAt を更新する', async () => {
    let now = NOW;
    const store = new BatchCredentialPoolStore(new MemoryStorage(), () => now);
    const pool = await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      threshold: 3,
    });
    now = NOW + 60_000;
    const updated = await store.recordRefill(pool.id, 5);
    expect(updated).toEqual({ ...pool, totalCount: 15, refreshedAt: NOW + 60_000 });
  });

  test('未存在の id は null を返す（冪等）', async () => {
    const store = newStore();
    expect(await store.recordRefill('missing', 5)).toBeNull();
  });
});

describe('BatchCredentialPoolStore.recordConsumption', () => {
  test('usedCount を既定 1 件加算し refreshedAt は更新しない', async () => {
    const store = newStore();
    const pool = await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      threshold: 3,
    });
    const updated = await store.recordConsumption(pool.id);
    expect(updated).toEqual({ ...pool, usedCount: 1 });
  });

  test('count を指定するとその件数を加算する', async () => {
    const store = newStore();
    const pool = await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      threshold: 3,
      usedCount: 2,
    });
    const updated = await store.recordConsumption(pool.id, 3);
    expect(updated?.usedCount).toBe(5);
  });

  test('未存在の id は null を返す（冪等）', async () => {
    const store = newStore();
    expect(await store.recordConsumption('missing')).toBeNull();
  });
});

describe('BatchCredentialPoolStore.remove', () => {
  test('削除後は get が null を返す', async () => {
    const store = newStore();
    const pool = await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      threshold: 3,
    });
    await store.remove(pool.id);
    expect(await store.get(pool.id)).toBeNull();
  });

  test('未存在の id を削除しても例外にならない（冪等）', async () => {
    const store = newStore();
    await expect(store.remove('missing')).resolves.toBeUndefined();
  });
});

describe('BatchCredentialPoolStore の破損データ', () => {
  test('storage 上の JSON が破損している場合は 6005 を投げる', async () => {
    const storage = new MemoryStorage();
    const store = new BatchCredentialPoolStore(storage);
    const pool = await store.create({
      vct: 'urn:eudi:pid:1',
      issuerDID: 'did:example:issuer',
      totalCount: 10,
      threshold: 3,
    });
    await storage.set(`eudi/batch/pool/${pool.id}`, new TextEncoder().encode('not-json'));
    await expect(store.get(pool.id)).rejects.toThrow(VericertsError);
    try {
      await store.get(pool.id);
      throw new Error('expected rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(VericertsError);
      expect((error as VericertsError).code).toBe(ErrorCodes.STORAGE_RECORD_CORRUPTED);
    }
  });

  test('必須フィールド欠落は 6005 を投げる', async () => {
    const storage = new MemoryStorage();
    const store = new BatchCredentialPoolStore(storage);
    await storage.set(
      'eudi/batch/pool/broken',
      new TextEncoder().encode(JSON.stringify({ id: 'broken', vct: 'urn:eudi:pid:1' })),
    );
    await expect(store.get('broken')).rejects.toThrow(VericertsError);
  });
});

describe('BatchCredentialPoolStore 数値入力の検証', () => {
  const base = {
    vct: 'urn:eudi:pid:1',
    issuerDID: 'did:example:issuer',
    totalCount: 5,
    threshold: 2,
  };

  test.each([
    ['totalCount NaN', { totalCount: Number.NaN }],
    ['totalCount 負値', { totalCount: -1 }],
    ['totalCount 小数', { totalCount: 1.5 }],
    ['threshold Infinity', { threshold: Number.POSITIVE_INFINITY }],
    ['usedCount NaN', { usedCount: Number.NaN }],
    ['usedCount が totalCount 超過', { usedCount: 6 }],
  ])('create は %s を RangeError で拒否し何も永続化しない', async (_name, override) => {
    const store = newStore();
    await expect(store.create({ ...base, ...override })).rejects.toBeInstanceOf(RangeError);
    expect(await store.list()).toEqual([]);
  });

  test.each([
    ['NaN', Number.NaN],
    ['負値', -1000],
    ['小数', 0.5],
    ['Infinity', Number.POSITIVE_INFINITY],
  ])('recordConsumption は count=%s を拒否し、既存プールと list を破損させない', async (_name, count) => {
    const store = newStore();
    const pool = await store.create(base);
    await expect(store.recordConsumption(pool.id, count)).rejects.toBeInstanceOf(RangeError);
    expect(await store.get(pool.id)).toEqual(pool);
    expect(await store.list()).toEqual([pool]);
  });

  test('recordConsumption は totalCount を超える消費を拒否する（残数が負にならない）', async () => {
    const store = newStore();
    const pool = await store.create(base);
    await expect(store.recordConsumption(pool.id, 999)).rejects.toBeInstanceOf(RangeError);
    expect((await store.get(pool.id))?.usedCount).toBe(0);
    expect((await store.recordConsumption(pool.id, 5))?.usedCount).toBe(5);
  });

  test.each([
    ['NaN', Number.NaN],
    ['負値', -1],
    ['小数', 1.5],
    ['安全整数超過', Number.MAX_SAFE_INTEGER],
  ])('recordRefill は addedCount=%s を拒否し、既存プールを変更しない', async (_name, added) => {
    const store = newStore();
    const pool = await store.create(base);
    await expect(store.recordRefill(pool.id, added)).rejects.toBeInstanceOf(RangeError);
    expect(await store.get(pool.id)).toEqual(pool);
  });
});
