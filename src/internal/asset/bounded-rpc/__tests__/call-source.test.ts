import { describe, expect, test } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { MAX_DOCUMENT_BYTES } from '../../../http/body-limit.js';
import { keccak256 } from '../../../keymanager/address.js';
import { bytesToHex, decodeHexDigits } from '../../hex-codec.js';
import { createBoundedRpcCallSource } from '../call-source.js';

const TOKEN = '0x2222222222222222222222222222222222222222';
const HOLDER = '0x1111111111111111111111111111111111111111';

interface Sent {
  method: string;
  params: unknown[];
  aborted: () => boolean;
}

/** JSON-RPC メソッド名 → result を返す fake fetch。送信内容と本文の読み取り量を記録する。 */
function rpcFetch(results: Record<string, unknown>, sent: Sent[] = []): FetchLike {
  return (async (_url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body)) as { id: number; method: string; params: unknown[] };
    sent.push({
      method: req.method,
      params: req.params,
      aborted: () => (init.signal as AbortSignal).aborted,
    });
    return new Response(
      JSON.stringify({ jsonrpc: '2.0', id: req.id, result: results[req.method] }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    );
  }) as unknown as FetchLike;
}

/** `chunkCount` 個の `chunkBytes` バイトのチャンクを流す応答。pull された回数を `pulls` に数える。 */
function streamingResponse(
  chunkCount: number,
  chunkBytes: number,
  pulls: { n: number },
): FetchLike {
  const prefix = new TextEncoder().encode('{"jsonrpc":"2.0","id":1,"result":"0x');
  const filler = new Uint8Array(chunkBytes).fill(0x30);
  return (async () => {
    let sentPrefix = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls.n += 1;
        if (!sentPrefix) {
          sentPrefix = true;
          controller.enqueue(prefix);
          return;
        }
        if (pulls.n > chunkCount) {
          controller.enqueue(new TextEncoder().encode('"}'));
          controller.close();
          return;
        }
        controller.enqueue(filler);
      },
    });
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  }) as unknown as FetchLike;
}

const URLS = { 1: 'https://rpc.example/' } as const;

describe('createBoundedRpcCallSource: 正常系', () => {
  test('call は eth_call の hex 結果を返し、latest を指定する', async () => {
    const sent: Sent[] = [];
    const source = createBoundedRpcCallSource(URLS, rpcFetch({ eth_call: '0x01ff' }, sent));
    await expect(source.call({ chainId: 1, to: TOKEN, data: '0xabcd' })).resolves.toBe('0x01ff');
    expect(sent).toHaveLength(1);
    expect(sent[0]?.params).toEqual([{ to: TOKEN, data: '0xabcd' }, 'latest']);
  });

  test('call は空戻り値 0x も返す', async () => {
    const source = createBoundedRpcCallSource(URLS, rpcFetch({ eth_call: '0x' }));
    await expect(source.call({ chainId: 1, to: TOKEN, data: '0x' })).resolves.toBe('0x');
  });

  test('nativeBalance は quantity を bigint にする', async () => {
    const source = createBoundedRpcCallSource(URLS, rpcFetch({ eth_getBalance: '0x2a' }));
    await expect(source.nativeBalance(1, HOLDER)).resolves.toBe(42n);
  });

  test('fetchTxParams は nonce / gasLimit / gasPrice を返す', async () => {
    const sent: Sent[] = [];
    const source = createBoundedRpcCallSource(
      URLS,
      rpcFetch(
        { eth_getTransactionCount: '0x5', eth_estimateGas: '0x186a0', eth_gasPrice: '0x3b9aca00' },
        sent,
      ),
    );
    await expect(
      source.fetchTxParams(1, HOLDER, { to: TOKEN, data: '0x', value: 255n }),
    ).resolves.toEqual({ nonce: 5, gasLimit: 100_000n, gasPrice: 1_000_000_000n });
    const estimate = sent.find((s) => s.method === 'eth_estimateGas');
    expect(estimate?.params).toEqual([{ from: HOLDER, to: TOKEN, data: '0x', value: '0xff' }]);
  });

  test('send は送信した Tx の keccak256 と一致するハッシュを返す', async () => {
    const raw = '0x02f8aabbcc';
    const hash = bytesToHex(keccak256(decodeHexDigits(raw.slice(2))));
    const source = createBoundedRpcCallSource(URLS, rpcFetch({ eth_sendRawTransaction: hash }));
    await expect(source.send({ chainId: 1, rawTransaction: raw })).resolves.toBe(hash);
  });

  test('未設定チェーンはネットワークに触れず 4071', async () => {
    let calls = 0;
    const source = createBoundedRpcCallSource(URLS, (async () => {
      calls += 1;
      throw new Error('unreachable');
    }) as unknown as FetchLike);
    await expect(source.call({ chainId: 999, to: TOKEN, data: '0x' })).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_NOT_CONFIGURED,
    });
    await expect(source.nativeBalance(999, HOLDER)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_NOT_CONFIGURED,
    });
    expect(calls).toBe(0);
  });

  test('継承プロパティ（Object.prototype）経由のチェーンは未設定扱い', async () => {
    const source = createBoundedRpcCallSource({}, rpcFetch({ eth_call: '0x' }));
    await expect(
      source.call({ chainId: '__proto__' as unknown as number, to: TOKEN, data: '0x' }),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_NOT_CONFIGURED });
  });
});

describe('createBoundedRpcCallSource: 本文サイズ上限', () => {
  // 形状を変える: (チャンク数, チャンクサイズ)。いずれも合計 > 1 MiB。
  // 読み取りは上限+1 チャンク程度で打ち切られる（pull 回数が決定的に上限付近で止まる）。
  test.each([
    ['少数の巨大チャンク', 10, MAX_DOCUMENT_BYTES],
    ['多数の極小チャンク', 40_000, 64],
    ['中間サイズ', 40, 65_536],
  ])('%s: 上限超過は 1021 で拒否し、読み取りを上限付近で打ち切る', async (_label, chunks, size) => {
    const pulls = { n: 0 };
    const source = createBoundedRpcCallSource(URLS, streamingResponse(chunks, size, pulls));
    await expect(source.call({ chainId: 1, to: TOKEN, data: '0x' })).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
    // 上限を超えるのに必要な最小チャンク数 + 余裕（prefix / 先読み）以内でしか pull されない。
    const needed = Math.ceil(MAX_DOCUMENT_BYTES / size) + 1;
    expect(pulls.n).toBeLessThanOrEqual(needed + 4);
    expect(pulls.n).toBeLessThan(chunks);
  });

  test('content-length で上限超過を申告する応答は本文を読まず 1021', async () => {
    // ReadableStream は構築時に 1 回だけ先読み（highWaterMark=1）する。それ以降は pull されない。
    const pulls = { n: 0 };
    const fetchImpl = (async () => {
      const body = new ReadableStream<Uint8Array>({
        pull() {
          pulls.n += 1;
        },
      });
      return new Response(body, {
        status: 200,
        headers: { 'content-type': 'application/json', 'content-length': String(25 * 1024 * 1024) },
      });
    }) as unknown as FetchLike;
    const source = createBoundedRpcCallSource(URLS, fetchImpl);
    await expect(source.call({ chainId: 1, to: TOKEN, data: '0x' })).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
    expect(pulls.n).toBeLessThanOrEqual(1);
  });

  test('上限以内の大きな eth_call 結果（約 512 KiB）は受理する', async () => {
    const big = `0x${'ab'.repeat(256 * 1024)}`;
    const source = createBoundedRpcCallSource(URLS, rpcFetch({ eth_call: big }));
    await expect((await source.call({ chainId: 1, to: TOKEN, data: '0x' })).length).toBe(
      big.length,
    );
  });
});

describe('createBoundedRpcCallSource: 結果の形状検査', () => {
  test.each([
    ['非文字列', 5],
    ['0x なし', 'deadbeef'],
    ['奇数桁', '0xabc'],
    ['非 hex', '0xzz'],
    ['null', null],
  ])('call: %s は 1021', async (_label, result) => {
    const source = createBoundedRpcCallSource(URLS, rpcFetch({ eth_call: result }));
    await expect(source.call({ chainId: 1, to: TOKEN, data: '0x' })).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });

  test.each([
    ['空 quantity', '0x'],
    ['257 ビット', `0x1${'0'.repeat(64)}`],
    ['10 進文字列', '42'],
    ['数値', 42],
  ])('nativeBalance: %s は 1021', async (_label, result) => {
    const source = createBoundedRpcCallSource(URLS, rpcFetch({ eth_getBalance: result }));
    await expect(source.nativeBalance(1, HOLDER)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });

  test('fetchTxParams: nonce が安全整数を超えると 1021', async () => {
    const source = createBoundedRpcCallSource(
      URLS,
      rpcFetch({
        eth_getTransactionCount: '0x20000000000000',
        eth_estimateGas: '0x1',
        eth_gasPrice: '0x1',
      }),
    );
    await expect(
      source.fetchTxParams(1, HOLDER, { to: TOKEN, data: '0x', value: 0n }),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_SUBMIT_FAILED });
  });

  test('fetchTxParams: eth_gasPrice が欠落（undefined）すると 1021', async () => {
    const source = createBoundedRpcCallSource(
      URLS,
      rpcFetch({ eth_getTransactionCount: '0x1', eth_estimateGas: '0x1' }),
    );
    await expect(
      source.fetchTxParams(1, HOLDER, { to: TOKEN, data: '0x', value: 0n }),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_SUBMIT_FAILED });
  });

  test('send: 別 Tx のハッシュを返す応答は 1021', async () => {
    const source = createBoundedRpcCallSource(
      URLS,
      rpcFetch({ eth_sendRawTransaction: `0x${'ab'.repeat(32)}` }),
    );
    await expect(source.send({ chainId: 1, rawTransaction: '0x02aabb' })).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });

  test('send: hex でない rawTransaction はネットワーク前に 1021', async () => {
    const sent: Sent[] = [];
    const source = createBoundedRpcCallSource(URLS, rpcFetch({}, sent));
    await expect(source.send({ chainId: 1, rawTransaction: 'not-hex' })).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
    expect(sent).toHaveLength(0);
  });
});
