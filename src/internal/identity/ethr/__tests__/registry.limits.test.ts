/**
 * did:ethr 解決の取得コストの上限。
 *
 * 署名検証前に攻撃者が選べる identity のイベントは安価に水増しできる。ログ件数・本文サイズ・応答時間に
 * 上限が無いと、1 解決で秒単位の停止と GB 級のヒープ消費（RPC 無応答なら ethers 既定の 300 秒）になる。
 * 実時間ではなく件数・abort の発火という決定的な事象で pin する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { JSON_RPC_TIMEOUT_MS } from '../../../http/json-rpc.js';
import { MAX_ERC1056_EVENTS } from '../events.js';
import { createEthersEventSource } from '../registry.js';
import { attributeLog, CHAIN_ID, IDENTITY, RPC_URL, rpcStub, toBytes32 } from './rpc-stub.js';

const NAME = toBytes32('did/svc/Svc');

function attributeLogs(count: number): unknown[] {
  return Array.from({ length: count }, (_, i) => attributeLog(NAME, '0x01', 1, 1 + i, 0));
}

async function codeOf(promise: Promise<unknown>): Promise<VericertsError['code'] | undefined> {
  try {
    await promise;
  } catch (error) {
    return (error as VericertsError).code;
  }
  return undefined;
}

describe('createEthersEventSource: ログ件数上限', () => {
  it(`上限ちょうど（${MAX_ERC1056_EVENTS} 件）は受理する`, async () => {
    const { fetchImpl } = rpcStub({ attribute: attributeLogs(MAX_ERC1056_EVENTS) });
    const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
    const events = await source.fetchEvents(CHAIN_ID, IDENTITY);
    expect(events.attributeChanges).toHaveLength(MAX_ERC1056_EVENTS);
  });

  it('上限を 1 件超えると、デコード前に DID_DOC_INVALID で拒否する（部分採用しない）', async () => {
    const { fetchImpl } = rpcStub({ attribute: attributeLogs(MAX_ERC1056_EVENTS + 1) });
    const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
    expect(await codeOf(source.fetchEvents(CHAIN_ID, IDENTITY))).toBe(ErrorCodes.DID_DOC_INVALID);
  });

  it('owner と attribute の合計で上限を数える', async () => {
    const { fetchImpl } = rpcStub({
      owner: Array.from({ length: 600 }, () => ({})),
      attribute: attributeLogs(401),
    });
    const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
    // 壊れた owner ログのデコードに入る前に件数で落ちる（DID_NOT_FOUND ではなく DID_DOC_INVALID）。
    expect(await codeOf(source.fetchEvents(CHAIN_ID, IDENTITY))).toBe(ErrorCodes.DID_DOC_INVALID);
  });
});

describe('createEthersEventSource: 応答サイズ・時間の上限', () => {
  it('本文が 1 MiB を超える応答は読み切らず DID_NOT_FOUND', async () => {
    let chunksServed = 0;
    const fetchImpl: FetchLike = async () => {
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          chunksServed++;
          controller.enqueue(new Uint8Array(64 * 1024).fill(0x20));
        },
      });
      return new Response(stream, { status: 200 });
    };
    const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
    expect(await codeOf(source.fetchEvents(CHAIN_ID, IDENTITY))).toBe(ErrorCodes.DID_NOT_FOUND);
    // 無限ストリームでも上限（1 MiB = 16 チャンク）付近で打ち切って読むのをやめる。
    expect(chunksServed).toBeLessThan(64);
  });

  it('RPC が応答しない場合は abort され DID_NOT_FOUND（ethers 既定の 300 秒に依存しない）', async () => {
    const realSetTimeout = globalThis.setTimeout;
    const delays: number[] = [];
    // タイムアウト用タイマーだけ即時発火に差し替え、設定された待ち時間を記録する。
    globalThis.setTimeout = ((fn: () => void, ms?: number) => {
      delays.push(ms ?? 0);
      return realSetTimeout(fn, 0);
    }) as unknown as typeof setTimeout;
    try {
      const fetchImpl: FetchLike = (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new Error('aborted')));
        });
      const source = createEthersEventSource({ [CHAIN_ID]: RPC_URL }, undefined, fetchImpl);
      expect(await codeOf(source.fetchEvents(CHAIN_ID, IDENTITY))).toBe(ErrorCodes.DID_NOT_FOUND);
    } finally {
      globalThis.setTimeout = realSetTimeout;
    }
    expect(delays).toContain(JSON_RPC_TIMEOUT_MS);
    expect(JSON_RPC_TIMEOUT_MS).toBeLessThanOrEqual(10_000);
  });
});
