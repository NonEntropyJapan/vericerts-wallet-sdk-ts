/**
 * createFetchBundlerRpc（fetch ベース BundlerRpc 既定実装）のユニットテスト。
 *
 * fetch を注入し実ネットワーク非依存で検証する。
 */

import { describe, expect, spyOn, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { createFetchBundlerRpc, type FetchLike } from '../fetch-adapter.js';

const URL = 'https://bundler.example/rpc';

/** 記録付き fake fetch。 */
function fakeFetch(responder: (body: unknown) => { ok?: boolean; json: unknown }): {
  fetch: FetchLike;
  bodies: unknown[];
} {
  const bodies: unknown[] = [];
  const fetch: FetchLike = async (_input, init) => {
    const parsed = JSON.parse(init.body);
    bodies.push(parsed);
    const r = responder(parsed);
    return new Response(JSON.stringify(r.json), {
      status: r.ok === false ? 500 : 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { fetch, bodies };
}

describe('createFetchBundlerRpc', () => {
  test('JSON-RPC 2.0 リクエストを組み立て result を返す', async () => {
    const { fetch, bodies } = fakeFetch(() => ({
      json: { jsonrpc: '2.0', id: 1, result: '0xok' },
    }));
    const rpc = createFetchBundlerRpc(URL, fetch);
    const result = await rpc.request('eth_sendUserOperation', [{ a: 1 }, '0xep']);
    expect(result).toBe('0xok');
    const sent = bodies[0] as Record<string, unknown>;
    expect(sent.jsonrpc).toBe('2.0');
    expect(sent.method).toBe('eth_sendUserOperation');
    expect(sent.params).toEqual([{ a: 1 }, '0xep']);
  });

  test('リクエスト ID を連番でインクリメントする', async () => {
    const { fetch, bodies } = fakeFetch(() => ({ json: { result: '0x' } }));
    const rpc = createFetchBundlerRpc(URL, fetch);
    await rpc.request('m', []);
    await rpc.request('m', []);
    expect((bodies[0] as Record<string, unknown>).id).toBe(1);
    expect((bodies[1] as Record<string, unknown>).id).toBe(2);
  });

  test('Bundler の JSON-RPC error は 7002 BUNDLER_REJECTED に正規化し本文を伝播しない', async () => {
    const { fetch } = fakeFetch(() => ({
      json: { error: { code: -32000, message: 'secret 0xdeadbeef reason' } },
    }));
    const rpc = createFetchBundlerRpc(URL, fetch);
    try {
      await rpc.request('m', []);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('7002');
      expect((e as VericertsError).message).not.toContain('secret');
      expect((e as VericertsError).cause).toBeUndefined();
    }
  });

  test('HTTP 非 200 は 1021', async () => {
    const { fetch } = fakeFetch(() => ({ ok: false, json: {} }));
    const rpc = createFetchBundlerRpc(URL, fetch);
    await expect(rpc.request('m', [])).rejects.toThrow(VericertsError);
  });

  test('トランスポート例外は 1021 に正規化する', async () => {
    const fetch: FetchLike = async () => {
      throw new Error('ECONNREFUSED 10.0.0.1');
    };
    const rpc = createFetchBundlerRpc(URL, fetch);
    try {
      await rpc.request('m', []);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as VericertsError).code).toBe('1021');
      expect((e as VericertsError).message).not.toContain('10.0.0.1');
    }
  });

  test('object でない payload は 1021', async () => {
    const { fetch } = fakeFetch(() => ({ json: 'not-json-object' }));
    const rpc = createFetchBundlerRpc(URL, fetch);
    await expect(rpc.request('m', [])).rejects.toThrow(VericertsError);
  });
});

/**
 * タイムアウト・本文上限・seam のレシーバ束縛。
 *
 * `auth/siwe/siwe-erc1271-adapter.ts` と同じ硬化が UserOp 送信経路にも効いていることを固定する。
 */
describe('createFetchBundlerRpc: 硬化', () => {
  test('固定タイムアウト（10 秒）で abort が予約され、到達時に 1021 に正規化する', async () => {
    // setTimeout の呼び出しそのものを捕捉し、実時間で待たずに手動発火する。
    // （即時発火にすり替える方式だと、signal 未実装時は `init.signal` が undefined になり
    //  別の TypeError で「たまたま」1021 に落ちてしまい、タイムアウト未実装を検出できない。）
    let scheduled: { readonly fn: () => void; readonly ms: number | undefined } | undefined;
    const setTimeoutSpy = spyOn(globalThis, 'setTimeout').mockImplementation(((
      fn: () => void,
      ms?: number,
    ) => {
      scheduled = { fn, ms };
      return 0 as unknown as ReturnType<typeof globalThis.setTimeout>;
    }) as typeof globalThis.setTimeout);
    try {
      // 応答を返さない Bundler（ヘッダも本文も返さない）。abort でのみ決着する。
      const fetch: FetchLike = (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => {
            reject(new DOMException('The operation was aborted.', 'AbortError'));
          });
        });
      const rpc = createFetchBundlerRpc(URL, fetch);
      const pending = rpc.request('eth_sendUserOperation', []);
      expect(scheduled).toBeDefined();
      expect(scheduled?.ms).toBe(10_000);
      scheduled?.fn();
      await expect(pending).rejects.toMatchObject({ code: ErrorCodes.CHAIN_SUBMIT_FAILED });
    } finally {
      setTimeoutSpy.mockRestore();
    }
  });

  test('1 MiB を超える応答本文は 1021（content-length を宣言しない場合も実バイト数で打ち切る）', async () => {
    const oversized = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: `0x${'a'.repeat(1_048_576)}`,
    });
    const fetch: FetchLike = () =>
      Promise.resolve(
        new Response(oversized, {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    const rpc = createFetchBundlerRpc(URL, fetch);
    await expect(rpc.request('m', [])).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });

  test('seam を裸で呼ばず、解決したレシーバを束ねて呼ぶ（this 参照つき実装が壊れない）', async () => {
    let seen: unknown = 'never-called';
    // メソッドとして定義された（= `this` を参照し得る）実装。裸呼び出しだと ESM は strict なので
    // `this` が undefined になり、`this.…` を読む実装は TypeError → 幻の 1021 になる。
    const source = {
      fetchImpl(this: unknown): Promise<Response> {
        seen = this;
        return Promise.resolve(
          new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0xok' }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        );
      },
    };
    const rpc = createFetchBundlerRpc(URL, source.fetchImpl as unknown as FetchLike);
    await rpc.request('m', []);
    expect(seen).toBeDefined();
    expect((seen as { fetchImpl?: unknown }).fetchImpl).toBe(source.fetchImpl);
  });
});
