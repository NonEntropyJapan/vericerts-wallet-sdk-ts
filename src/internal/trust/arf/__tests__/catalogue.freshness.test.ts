/**
 * ARF Catalogue の鮮度・世代の検査（TSL の）。
 *
 * 署名は固定鍵で永続的に有効なので、登録解除前に署名された旧 Catalogue は署名検証を通る。
 * `nextUpdate` の期限切れと、直前に受理した世代（`previous`）からの後退を 10305 で拒否する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { ArfCatalogueGeneration } from '../arf-types.js';
import { loadArfTrustAnchor } from '../catalogue.js';
import { type CataloguePayload, makeKeyPair, signedCatalogue } from './arf-fixtures.js';

const KEY = makeKeyPair(5);
const NOW = Date.parse('2026-10-01T00:00:00Z') / 1000;
const ENTRIES = [{ id: 'https://wp.example.eu', role: 'wallet-provider' }];

function load(
  payload: Omit<CataloguePayload, 'entries'>,
  options: { previous?: ArfCatalogueGeneration } = {},
) {
  const body = signedCatalogue({ ...payload, entries: ENTRIES }, KEY);
  return loadArfTrustAnchor('https://arf.example/anchor.json', {
    fetcher: async () => body,
    trustAnchorPublicKey: KEY.publicKey,
    nowSeconds: NOW,
    ...options,
  });
}

async function expectRejected(promise: Promise<unknown>): Promise<void> {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(VericertsError);
  expect((error as VericertsError).code).toBe(ErrorCodes.ARF_TRUST_ANCHOR_NOT_REGISTERED);
}

describe('loadArfTrustAnchor: nextUpdate（期限切れの世代）', () => {
  test('期限内なら受理し、世代情報を結果に載せる', async () => {
    const result = await load({
      sequence: 7,
      issuedAt: '2026-09-30T00:00:00Z',
      nextUpdate: '2026-10-02T00:00:00Z',
    });

    expect(result).toMatchObject({
      sequence: 7,
      issuedAt: '2026-09-30T00:00:00Z',
      nextUpdate: '2026-10-02T00:00:00Z',
    });
  });

  test('nextUpdate を過ぎた Catalogue（境界ちょうどを含む）は拒否する', async () => {
    await expectRejected(load({ nextUpdate: '2026-09-30T23:59:59Z' }));
    await expectRejected(load({ nextUpdate: '2026-10-01T00:00:00Z' }));
  });

  test('項目を提供しない従来の Catalogue は受理する（後方互換）', async () => {
    const result = await load({});

    expect(result.sequence).toBeUndefined();
    expect(result.issuedAt).toBeUndefined();
    expect(result.entries).toHaveLength(1);
  });

  test.each([
    ['sequence が負', { sequence: -1 }],
    ['sequence が小数', { sequence: 1.5 }],
    ['sequence が文字列', { sequence: '7' }],
    ['sequence が安全整数を超える', { sequence: 2 ** 60 }],
    ['issuedAt がオフセット無し', { issuedAt: '2026-09-30T00:00:00' }],
    ['issuedAt が非文字列', { issuedAt: 1 }],
    ['nextUpdate が不正な日付', { nextUpdate: 'tomorrow' }],
    ['nextUpdate が null', { nextUpdate: null }],
  ])('提供されたが不正な項目（%s）は無視せず拒否する', async (_label, payload) => {
    await expectRejected(load(payload));
  });
});

describe('loadArfTrustAnchor: previous（世代ロールバック拒否）', () => {
  test('sequence が後退した旧世代は拒否する', async () => {
    await expectRejected(load({ sequence: 6 }, { previous: { sequence: 7 } }));
  });

  test('sequence が進む・同値の世代は受理する', async () => {
    expect((await load({ sequence: 8 }, { previous: { sequence: 7 } })).sequence).toBe(8);
    expect((await load({ sequence: 7 }, { previous: { sequence: 7 } })).sequence).toBe(7);
  });

  test('sequence が進んでいれば issuedAt が古くても受理し、同値なら issuedAt で比較する', async () => {
    const previous = { sequence: 7, issuedAt: '2026-09-30T00:00:00Z' };

    await load({ sequence: 8, issuedAt: '2026-09-01T00:00:00Z' }, { previous });
    await expectRejected(load({ sequence: 7, issuedAt: '2026-09-29T00:00:00Z' }, { previous }));
    await load({ sequence: 7, issuedAt: '2026-09-30T00:00:00Z' }, { previous });
  });

  test('直前が sequence を持つのに今回その項目を消した世代は拒否する（比較の迂回）', async () => {
    await expectRejected(load({}, { previous: { sequence: 7 } }));
    await expectRejected(load({ issuedAt: '2026-09-30T00:00:00Z' }, { previous: { sequence: 7 } }));
  });

  test('sequence の無い Catalogue でも issuedAt の後退は拒否する', async () => {
    const previous = { issuedAt: '2026-09-30T00:00:00Z' };

    await expectRejected(load({ issuedAt: '2026-09-29T00:00:00Z' }, { previous }));
    await expectRejected(load({}, { previous }));
    await load(
      { issuedAt: '2026-09-30T12:00:00+09:00' },
      { previous: { issuedAt: '2026-09-29T00:00:00Z' } },
    );
  });

  test('直前の世代に比較できる項目が無ければ従来どおり受理する', async () => {
    await load({ sequence: 1 }, { previous: {} });
    await load({}, { previous: {} });
  });
});
