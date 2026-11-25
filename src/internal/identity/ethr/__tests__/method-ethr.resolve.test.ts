/**
 * MethodEthr / resolveDidEthr の解決検証（モック EventSource 注入、network 非依存）。
 *
 * 固定イベント → 期待 DID Document（複数ネットワーク Mainnet / Arbitrum）、
 * fetchEvents が正しい (chainId, address) で呼ばれること、clock 注入で validTo 評価が
 * 決定的になることを確認する（マルチネットワーク解決 / イベントスキャン）。
 */

import { describe, expect, it } from 'bun:test';
import type { Erc1056Events } from '../events.js';
import { MethodEthr, resolveDidEthr } from '../method-ethr.js';
import type { Erc1056EventSource } from '../registry.js';

const IDENTITY = '0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb';
const SECP_PUBKEY_HEX = '0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71';
const NOW_SECONDS = 1_700_000_000;
const NOW_MS = NOW_SECONDS * 1000;

/** 固定イベントを返すモック EventSource。呼び出し引数を記録する。 */
function mockSource(
  events: Erc1056Events,
): Erc1056EventSource & { calls: Array<{ chainId: number; address: string }> } {
  const calls: Array<{ chainId: number; address: string }> = [];
  return {
    calls,
    async fetchEvents(chainId, address) {
      calls.push({ chainId, address });
      return events;
    },
  };
}

const sampleEvents: Erc1056Events = {
  ownerChanges: [],
  attributeChanges: [
    {
      name: 'did/pub/Secp256k1/veriKey/hex',
      value: SECP_PUBKEY_HEX,
      validTo: NOW_SECONDS + 10000,
      blockNumber: 10,
      logIndex: 0,
    },
  ],
};

describe('resolveDidEthr', () => {
  it('Mainnet（省略形）を解決する', async () => {
    const source = mockSource(sampleEvents);
    const did = `did:ethr:${IDENTITY}`;
    const doc = await resolveDidEthr(did, source, NOW_SECONDS);
    expect(doc.id).toBe(did);
    expect(doc.controller).toBe(`did:ethr:1:${IDENTITY}`);
    expect(source.calls).toEqual([{ chainId: 1, address: IDENTITY }]);
    expect(doc.assertionMethod).toContain(`${did}#delegate-1`);
  });

  it('Arbitrum One（chainId 42161）を解決する', async () => {
    const source = mockSource(sampleEvents);
    const did = `did:ethr:42161:${IDENTITY}`;
    const doc = await resolveDidEthr(did, source, NOW_SECONDS);
    expect(doc.controller).toBe(`did:ethr:42161:${IDENTITY}`);
    expect(doc.verificationMethod[0]?.blockchainAccountId).toBe(`eip155:42161:${IDENTITY}`);
    expect(source.calls).toEqual([{ chainId: 42161, address: IDENTITY }]);
  });
});

describe('MethodEthr.resolve', () => {
  it('メソッド名は ethr', () => {
    expect(new MethodEthr({ rpcUrls: {} }).method()).toBe('ethr');
  });

  it('注入した clock で validTo を決定的に評価する（有効）', async () => {
    const source = mockSource(sampleEvents);
    const method = new MethodEthr({ rpcUrls: {}, eventSource: source, clock: () => NOW_MS });
    const doc = await method.resolve(`did:ethr:${IDENTITY}`);
    // validTo > now のため delegate が含まれる。
    expect(doc.verificationMethod).toHaveLength(2);
  });

  it('注入した clock で validTo を決定的に評価する（期限切れ）', async () => {
    const source = mockSource(sampleEvents);
    // 鍵の validTo より後の時刻を clock で与えると除外される。
    const method = new MethodEthr({
      rpcUrls: {},
      eventSource: source,
      clock: () => (NOW_SECONDS + 99999) * 1000,
    });
    const doc = await method.resolve(`did:ethr:${IDENTITY}`);
    expect(doc.verificationMethod).toHaveLength(1);
  });

  it('fetchEvents を正しい (chainId, address) で呼ぶ', async () => {
    const source = mockSource(sampleEvents);
    const method = new MethodEthr({ rpcUrls: {}, eventSource: source, clock: () => NOW_MS });
    await method.resolve(`did:ethr:42161:${IDENTITY}`);
    expect(source.calls).toEqual([{ chainId: 42161, address: IDENTITY }]);
  });
});
