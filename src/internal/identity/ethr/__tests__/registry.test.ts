/**
 * createEthersEventSource（registry.ts）の網羅テスト。
 *
 * `fetchImpl` に JSON-RPC の `eth_getLogs` 応答を返すスタブを注入し、実ネットワークに触れずに
 * fetchEvents の成功系（owner/attribute イベント正規化、registryAddresses 上書き）・
 * エラー正規化（cause 非伝播）・decodeBytes32 のデコード分岐（ゼロ終端の有無）を検証する。
 * 上限（件数・本文サイズ・タイムアウト）は registry.limits.test.ts。
 */

import { describe, expect, it } from 'bun:test';
import { zeroPadValue } from 'ethers';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { createEthersEventSource } from '../registry.js';
import {
  attributeLog,
  CHAIN_ID,
  IDENTITY,
  OWNER,
  ownerLog,
  RPC_URL,
  rpcStub,
  toBytes32,
} from './rpc-stub.js';

describe('createEthersEventSource.fetchEvents（成功系）', () => {
  it('owner/attribute イベントを Erc1056Events に正規化し、identity で絞った eth_getLogs を発行する', async () => {
    const { fetchImpl, requests } = rpcStub({
      owner: [ownerLog(OWNER, 100, 0)],
      attribute: [
        attributeLog(toBytes32('did/pub/Secp256k1/veriKey/hex'), '0xdeadbeef', 9999999999, 101, 1),
      ],
    });
    const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
    const events = await source.fetchEvents(CHAIN_ID, IDENTITY);

    expect(events.ownerChanges).toEqual([
      { owner: expect.stringMatching(/^0x1111/i), blockNumber: 100, logIndex: 0 },
    ]);
    expect(events.attributeChanges).toEqual([
      {
        name: 'did/pub/Secp256k1/veriKey/hex',
        value: '0xdeadbeef',
        validTo: 9999999999,
        blockNumber: 101,
        logIndex: 1,
      },
    ]);
    expect(requests).toHaveLength(2);
    for (const request of requests) {
      expect(request.url).toBe(RPC_URL);
      expect(request.body.method).toBe('eth_getLogs');
      expect(request.body.params[0].topics).toContain(zeroPadValue(IDENTITY, 32));
    }
  });

  it('registryAddresses で既定アドレスを上書きし、その address で問い合わせる', async () => {
    const override = '0x2222222222222222222222222222222222222222';
    const { fetchImpl, requests } = rpcStub({});
    const source = createEthersEventSource(
      { [CHAIN_ID]: RPC_URL },
      { [CHAIN_ID]: override },
      fetchImpl,
    );
    const events = await source.fetchEvents(CHAIN_ID, IDENTITY);
    expect(events).toEqual({ ownerChanges: [], attributeChanges: [] });
    expect(requests.every((r) => r.body.params[0].address === override)).toBe(true);
  });
});

describe('createEthersEventSource.fetchEvents（エラー正規化）', () => {
  it('fetch が一般的な Error を throw した場合は DID_NOT_FOUND に正規化する（cause を伝播しない）', async () => {
    const fetchImpl: FetchLike = async () => {
      throw new Error('rpc timeout: secret-rpc-token-abc123');
    };
    const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
    const error = await source.fetchEvents(CHAIN_ID, IDENTITY).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe(ErrorCodes.DID_NOT_FOUND);
    expect((error as VericertsError).message).not.toContain('secret-rpc-token-abc123');
  });

  it('JSON-RPC error 応答・result が配列でない応答・壊れたログは DID_NOT_FOUND', async () => {
    const respond =
      (payload: unknown): FetchLike =>
      async () =>
        new Response(JSON.stringify(payload), { status: 200 });
    for (const payload of [
      { jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'secret' } },
      { jsonrpc: '2.0', id: 1, result: 'nope' },
      {
        jsonrpc: '2.0',
        id: 1,
        result: [{ topics: [], data: '0x', blockNumber: '0x1', logIndex: '0x0' }],
      },
    ]) {
      const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, respond(payload));
      const error = await source.fetchEvents(CHAIN_ID, IDENTITY).catch((e: unknown) => e);
      expect((error as VericertsError).code).toBe(ErrorCodes.DID_NOT_FOUND);
    }
  });
});

describe('decodeBytes32（attribute name のデコード）', () => {
  it('ゼロ終端が無い場合は 32 バイト全体をデコードする', async () => {
    const fullBytes = 'a'.repeat(32); // 32 ascii 文字 = 32 バイト、ゼロバイト無し
    const { fetchImpl } = rpcStub({
      attribute: [
        attributeLog(`0x${Buffer.from(fullBytes, 'utf8').toString('hex')}`, '0x00', 1, 5, 0),
      ],
    });
    const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
    const events = await source.fetchEvents(CHAIN_ID, IDENTITY);
    expect(events.attributeChanges[0]?.name).toBe(fullBytes);
  });

  it('全ゼロの name は空文字列にデコードする', async () => {
    const { fetchImpl } = rpcStub({
      attribute: [attributeLog(`0x${'00'.repeat(32)}`, '0x00', 1, 6, 0)],
    });
    const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
    const events = await source.fetchEvents(CHAIN_ID, IDENTITY);
    expect(events.attributeChanges[0]?.name).toBe('');
  });
});
