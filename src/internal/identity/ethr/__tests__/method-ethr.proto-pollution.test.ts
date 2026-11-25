/**
 * MethodEthr / createEthersEventSource の `Object.prototype` 汚染耐性。
 *
 * `opts.eventSource ?? …` / `opts.registryAddresses` / `opts.fetchImpl` / `opts.clock` / `rpcUrls[chainId]` /
 * `registryAddresses?.[chainId]` が鎖読みだと、`Object.prototype` 汚染だけで **オプションを省略した正当な
 * 呼び出し**が攻撃者の eventSource（= 偽の controller）・RPC 宛先・レジストリ・時計を拾う。
 * 汚染の前後で結果が変わらないことを、汚染するキーと値の形（データ / 数値キー / アクセサ）を変えて固定する。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { MethodEthr } from '../method-ethr.js';
import {
  createEthersEventSource,
  DEFAULT_REGISTRY_ADDRESS,
  type Erc1056EventSource,
} from '../registry.js';
import { IDENTITY, OWNER, ownerLog, rpcStub } from './rpc-stub.js';

const ATTACKER_OWNER = '0x2222222222222222222222222222222222222222';
const ATTACKER_URL = 'http://attacker.example:8545';
const ATTACKER_REGISTRY = '0x3333333333333333333333333333333333333333';
const DID = `did:ethr:${IDENTITY}`;

/** 攻撃者が `Object.prototype.eventSource` に仕込む EventSource（偽の owner を返す）。 */
const attackerSource: Erc1056EventSource = {
  async fetchEvents() {
    return {
      ownerChanges: [{ owner: ATTACKER_OWNER, blockNumber: 1, logIndex: 0 }],
      attributeChanges: [],
    } as never;
  },
};

function attackerFetch(requested: string[]): FetchLike {
  return async (url) => {
    requested.push(url);
    throw new Error('attacker fetch must never be used');
  };
}

/** スタブが受けた `eth_getLogs` の `address`（レジストリアドレス）一覧。 */
function requestedAddresses(stub: ReturnType<typeof rpcStub>): string[] {
  return stub.requests.map((r) => String(r.body.params[0].address));
}

async function failureOf(promise: Promise<unknown>): Promise<VericertsError> {
  try {
    await promise;
  } catch (error) {
    return error as VericertsError;
  }
  throw new Error('should have thrown');
}

describe('MethodEthr: オプション省略時に継承値を拾わない', () => {
  it('Object.prototype.eventSource を汚染しても controller は RPC 応答（正規の owner）のまま', async () => {
    const stub = rpcStub({ owner: [ownerLog(OWNER, 5, 0)] });
    const method = new MethodEthr({ rpcUrls: { 1: 'http://rpc.example' } });
    // fetchImpl は own で渡せないため、グローバル fetch を差し替えて RPC 応答を返す。
    const original = globalThis.fetch;
    globalThis.fetch = ((url: string, init: RequestInit) =>
      stub.fetchImpl(url, init as never)) as unknown as typeof fetch;
    try {
      const clean = await method.resolve(DID);
      const polluted = await withPollutedPrototypeAsync({ eventSource: attackerSource }, () =>
        new MethodEthr({ rpcUrls: { 1: 'http://rpc.example' } }).resolve(DID),
      );
      expect(polluted).toEqual(clean);
      expect(JSON.stringify(polluted)).not.toContain(ATTACKER_OWNER.slice(2));
    } finally {
      globalThis.fetch = original;
    }
  });

  it.each([
    ['registryAddresses（数値キー 1 を持つ表）', { registryAddresses: { 1: ATTACKER_REGISTRY } }],
    ['rpcUrls（数値キー 1 を持つ表）', { rpcUrls: { 1: ATTACKER_URL } }],
  ] as const)('汚染された %s は RPC 宛先・レジストリに反映されない', async (_name, polluted) => {
    const stub = rpcStub({ owner: [ownerLog(OWNER, 5, 0)] });
    const source = createEthersEventSource({ 1: 'http://rpc.example' }, undefined, stub.fetchImpl);
    const method = new MethodEthr({ rpcUrls: {}, eventSource: source });
    const clean = await method.resolve(DID);
    const dirty = await withPollutedPrototypeAsync(polluted, () => method.resolve(DID));
    expect(dirty).toEqual(clean);
    expect(new Set(stub.requests.map((r) => r.url))).toEqual(new Set(['http://rpc.example']));
    expect(new Set(requestedAddresses(stub))).toEqual(new Set([DEFAULT_REGISTRY_ADDRESS]));
  });

  it('汚染された fetchImpl は RPC 往復に使われない（コンストラクタ経由で省略した場合）', async () => {
    const requested: string[] = [];
    const stub = rpcStub({ owner: [ownerLog(OWNER, 5, 0)] });
    const original = globalThis.fetch;
    globalThis.fetch = ((url: string, init: RequestInit) =>
      stub.fetchImpl(url, init as never)) as unknown as typeof fetch;
    try {
      await withPollutedPrototypeAsync({ fetchImpl: attackerFetch(requested) }, () =>
        new MethodEthr({ rpcUrls: { 1: 'http://rpc.example' } }).resolve(DID),
      );
    } finally {
      globalThis.fetch = original;
    }
    expect(requested).toHaveLength(0);
    expect(stub.requests.length).toBeGreaterThan(0);
  });

  it('Object.prototype.clock（アクセサ）を汚染しても時計は Date.now のまま', async () => {
    const seen: number[] = [];
    const source: Erc1056EventSource = {
      async fetchEvents() {
        return { ownerChanges: [], attributeChanges: [] };
      },
    };
    const before = Date.now();
    const doc = await withPollutedPrototypeAccessorAsync(
      {
        clock: () => () => {
          seen.push(1);
          return 0;
        },
      },
      () => new MethodEthr({ rpcUrls: {}, eventSource: source }).resolve(DID),
    );
    expect(seen).toHaveLength(0);
    expect(doc.id).toBe(DID);
    expect(Date.now()).toBeGreaterThanOrEqual(before);
  });
});

describe('createEthersEventSource: chainId 添字は自身のプロパティだけ引く', () => {
  it.each([
    ['1', 1],
    ['137', 137],
    ['42161', 42161],
  ] as const)('未設定チェーン %s は Object.prototype の数値キー汚染でも解決不能（2003）で RPC を送らない', async (key, chainId) => {
    const stub = rpcStub({ owner: [ownerLog(OWNER, 5, 0)] });
    const source = createEthersEventSource({}, undefined, stub.fetchImpl);
    const error = await withPollutedPrototypeAsync({ [key]: ATTACKER_URL }, () =>
      failureOf(source.fetchEvents(chainId, IDENTITY)),
    );
    expect(error.code).toBe(ErrorCodes.DID_NOT_FOUND);
    expect(stub.requests).toHaveLength(0);
  });

  it('registryAddresses に当該チェーンが無ければ、数値キー汚染ではなく既定レジストリへ問い合わせる', async () => {
    const stub = rpcStub({ owner: [ownerLog(OWNER, 5, 0)] });
    const source = createEthersEventSource(
      { 1: 'http://rpc.example' },
      { 137: '0xabc' },
      stub.fetchImpl,
    );
    await withPollutedPrototypeAsync({ 1: ATTACKER_REGISTRY }, () =>
      source.fetchEvents(1, IDENTITY),
    );
    const addresses = requestedAddresses(stub);
    expect(addresses.length).toBeGreaterThan(0);
    expect(new Set(addresses)).toEqual(new Set([DEFAULT_REGISTRY_ADDRESS]));
  });

  it('own で設定したチェーンは従来どおり引ける（正常系）', async () => {
    // 上書きしたレジストリからのログとして返す（address 検証は上書き先と照合する）。
    const stub = rpcStub({ owner: [{ ...ownerLog(OWNER, 5, 0), address: ATTACKER_REGISTRY }] });
    const source = createEthersEventSource(
      { 1: 'http://rpc.example' },
      { 1: ATTACKER_REGISTRY },
      stub.fetchImpl,
    );
    await source.fetchEvents(1, IDENTITY);
    expect(new Set(stub.requests.map((r) => r.url))).toEqual(new Set(['http://rpc.example']));
    const addresses = requestedAddresses(stub);
    expect(new Set(addresses)).toEqual(new Set([ATTACKER_REGISTRY]));
  });
});
