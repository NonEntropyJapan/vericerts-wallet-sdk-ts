/**
 * `isTrustedIssuer` / `TrustedIssuerListStore.createList` の汚染耐性。
 *
 * 省略しただけの正当な呼び出しが `Object.prototype` の汚染値を拾うと、期限切れ発行者が信頼される（`at`）、
 * 空のはずの新規リストへ攻撃者の発行者が入り永続化される（`trustedIssuers`）、採番が無効化されて
 * 既存リストが上書きされる（`id`）。いずれも汚染前後で結果が変わらないことで検証する。
 */

import { describe, expect, test } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAsync,
} from '../../__tests__/prototype-pollution.fixtures.js';
import { isTrustedIssuer, TrustedIssuerListStore } from '../trusted-issuer-list-store.js';
import type { TrustedIssuerEntry, TrustedIssuerList } from '../types.js';

const EXPIRED = 'did:web:expired.example';
const NOT_YET = 'did:web:future.example';
const FOREVER = 'did:web:forever.example';

function listOf(...trustedIssuers: TrustedIssuerEntry[]): TrustedIssuerList {
  return {
    id: 'l',
    type: 'TrustedIssuerList',
    version: 'TSLv1',
    listOperator: 'o',
    listName: 'n',
    issuedAt: '2026-01-01T00:00:00Z',
    trustedIssuers,
  };
}

const list = listOf(
  { id: EXPIRED, name: 'x', source: 'custom', validUntil: '2020-01-01T00:00:00Z' },
  { id: NOT_YET, name: 'y', source: 'custom', validFrom: '2999-01-01T00:00:00Z' },
  { id: FOREVER, name: 'z', source: 'custom', credentialTypes: ['University'] },
);

function memoryStore() {
  const map = new Map<string, Uint8Array>();
  const storage = {
    async get(key: string) {
      return map.get(key) ?? null;
    },
    async set(key: string, value: Uint8Array) {
      map.set(key, value);
    },
    async delete(key: string) {
      map.delete(key);
    },
    async list(prefix: string) {
      return [...map.keys()].filter((k) => k.startsWith(prefix));
    },
  };
  let n = 0;
  return new TrustedIssuerListStore(storage, undefined, () => `gen-${++n}`);
}

describe('isTrustedIssuer の汚染耐性', () => {
  test('options 省略時、汚染 at で期限切れ・未発効の発行者が信頼されない', () => {
    expect(isTrustedIssuer(list, EXPIRED)).toBe(false);
    expect(isTrustedIssuer(list, NOT_YET)).toBe(false);
    withPollutedPrototype({ at: new Date('2019-06-01T00:00:00Z') }, () => {
      expect(isTrustedIssuer(list, EXPIRED)).toBe(false);
    });
    withPollutedPrototype({ at: new Date('3000-01-01T00:00:00Z') }, () => {
      expect(isTrustedIssuer(list, NOT_YET)).toBe(false);
    });
  });

  test('空の options でも汚染 at / credentialType の影響を受けない', () => {
    withPollutedPrototype({ at: new Date('2019-06-01T00:00:00Z'), credentialType: 'Other' }, () => {
      expect(isTrustedIssuer(list, EXPIRED, {})).toBe(false);
      expect(isTrustedIssuer(list, FOREVER, {})).toBe(true);
    });
  });

  test('エントリの validUntil / validFrom / credentialTypes の汚染値は期間・種別判定を変えない', () => {
    const open = listOf({ id: 'did:web:open.example', name: 'o', source: 'custom' });
    withPollutedPrototype(
      {
        validUntil: '2020-01-01T00:00:00Z',
        validFrom: '2999-01-01T00:00:00Z',
        credentialTypes: [],
      },
      () => {
        expect(isTrustedIssuer(open, 'did:web:open.example', { credentialType: 'Any' })).toBe(true);
      },
    );
  });

  test('own の at は汚染値より優先される（正常系）', () => {
    withPollutedPrototype({ at: new Date('3000-01-01T00:00:00Z') }, () => {
      expect(isTrustedIssuer(list, EXPIRED, { at: new Date('2019-06-01T00:00:00Z') })).toBe(true);
    });
  });
});

describe('TrustedIssuerListStore.createList の汚染耐性', () => {
  test('trustedIssuers 省略時、汚染値の発行者は入らず永続化もされない', async () => {
    const store = memoryStore();
    const created = await withPollutedPrototypeAsync(
      { trustedIssuers: [{ id: 'did:web:evil.example', name: 'Evil', source: 'custom' }] },
      () => store.createList({ listOperator: 'did:web:op', listName: 'mine' }),
    );
    expect(created.trustedIssuers).toEqual([]);
    expect((await store.getList(created.id))?.trustedIssuers).toEqual([]);
    expect(isTrustedIssuer(created, 'did:web:evil.example')).toBe(false);
  });

  test('id 省略時の採番は汚染 id で無効化されず、複数リストが衝突しない', async () => {
    const store = memoryStore();
    const [a, b] = await withPollutedPrototypeAsync({ id: 'fixed-id' }, async () => [
      await store.createList({ listOperator: 'did:web:a', listName: 'A' }),
      await store.createList({ listOperator: 'did:web:b', listName: 'B' }),
    ]);
    expect([a?.id, b?.id]).toEqual(['gen-1', 'gen-2']);
    expect((await store.getList('gen-1'))?.listName).toBe('A');
  });

  test('nextUpdate / sourceUrl / intervalMs の汚染値は生えない', async () => {
    const store = memoryStore();
    const created = await withPollutedPrototypeAsync(
      { nextUpdate: '2999-01-01T00:00:00Z', sourceUrl: 'https://evil.example/l', intervalMs: 1 },
      () => store.createList({ listOperator: 'did:web:op', listName: 'mine' }),
    );
    for (const key of ['nextUpdate', 'sourceUrl', 'intervalMs']) {
      expect(Object.hasOwn(created, key)).toBe(false);
    }
  });

  test('own の入力は汚染値より優先される（正常系）', async () => {
    const store = memoryStore();
    const created = await withPollutedPrototypeAsync({ id: 'evil', trustedIssuers: [] }, () =>
      store.createList({
        id: 'mine',
        listOperator: 'did:web:op',
        listName: 'mine',
        trustedIssuers: [{ id: 'did:web:ok.example', name: 'ok', source: 'custom' }],
      }),
    );
    expect(created.id).toBe('mine');
    expect(created.trustedIssuers.map((e) => e.id)).toEqual(['did:web:ok.example']);
  });
});
