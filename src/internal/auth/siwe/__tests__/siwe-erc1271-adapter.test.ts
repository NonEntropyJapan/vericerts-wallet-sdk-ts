/**
 * fetch ベース Erc1271Rpc（eth_call）アダプタのユニットテスト。
 *
 * 検証内容:
 * - eth_call の JSON-RPC リクエスト形状（method / params[to,data] / latest）。
 * - 正常応答の result を返し、verifyErc1271Signature と結線して magicValue 検証まで通ること。
 * - HTTP 非 200 / JSON-RPC error / result 不正 / トランスポート失敗を 1021 に正規化すること。
 * - `Object.prototype` 汚染下で `result` / `error` の継承値を採用しないこと。
 * - aa の双子（`aa/fetch-adapter.ts`）と同じ硬化がこの経路にも効いていること。
 */

import { describe, expect, it, spyOn } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { Hex } from '../siwe.js';
import { createFetchErc1271Rpc, type Erc1271FetchLike } from '../siwe-erc1271-adapter.js';
import { verifyErc1271Signature } from '../siwe-verify.js';

const ACCOUNT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const OK_MAGIC = `0x1626ba7e${'0'.repeat(56)}` as Hex;

function fetchReturning(
  payload: unknown,
  ok = true,
): { fetch: Erc1271FetchLike; calls: unknown[] } {
  const calls: unknown[] = [];
  const fetch: Erc1271FetchLike = async (_url, init) => {
    calls.push(JSON.parse(init.body));
    return new Response(JSON.stringify(payload), {
      status: ok ? 200 : 500,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { fetch, calls };
}

describe('createFetchErc1271Rpc', () => {
  it('eth_call を latest ブロックで送り result を返す', async () => {
    const { fetch, calls } = fetchReturning({ jsonrpc: '2.0', id: 1, result: OK_MAGIC });
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    const result = await rpc.call(ACCOUNT, '0xabcd' as Hex);
    expect(result).toBe(OK_MAGIC);
    expect(calls[0]).toMatchObject({
      method: 'eth_call',
      params: [{ to: ACCOUNT, data: '0xabcd' }, 'latest'],
    });
  });

  it('verifyErc1271Signature と結線して magicValue を検証できる', async () => {
    const { fetch } = fetchReturning({ jsonrpc: '2.0', id: 1, result: OK_MAGIC });
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    const valid = await verifyErc1271Signature(rpc, 'siwe body', '0xdeadbeef' as Hex, ACCOUNT);
    expect(valid).toBe(true);
  });

  it('HTTP 非 200 は 1021', async () => {
    const { fetch } = fetchReturning({}, false);
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    await expect(rpc.call(ACCOUNT, '0x' as Hex)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });

  it('JSON-RPC error は 1021（本文を伝播しない）', async () => {
    const { fetch } = fetchReturning({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32000, message: 'secret 0xdeadbeef reason' },
    });
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    try {
      await rpc.call(ACCOUNT, '0x' as Hex);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe(ErrorCodes.CHAIN_SUBMIT_FAILED);
      expect((e as VericertsError).message).not.toContain('secret');
      expect((e as VericertsError).cause).toBeUndefined();
    }
  });

  it('result が hex でないと 1021', async () => {
    const { fetch } = fetchReturning({ jsonrpc: '2.0', id: 1, result: 42 });
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    await expect(rpc.call(ACCOUNT, '0x' as Hex)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });

  it('トランスポート失敗は 1021', async () => {
    const fetch: Erc1271FetchLike = async () => {
      throw new Error('network down');
    };
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    await expect(rpc.call(ACCOUNT, '0x' as Hex)).rejects.toBeInstanceOf(VericertsError);
  });
});

/**
 * タイムアウト機構。
 *
 * `jar/fetch-jar.ts` や `eudi/issuance/nonce.ts` と同じく、応答ヘッダだけ先に返して本文を
 * 引き延ばす相手に無期限に待たされないことを固定する。
 */
describe('createFetchErc1271Rpc: タイムアウト', () => {
  it('固定タイムアウト（10 秒）で abort が予約され、到達時に 1021 に正規化する', async () => {
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
      const fetch: Erc1271FetchLike = (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal.addEventListener('abort', () => {
            reject(new DOMException('The operation was aborted.', 'AbortError'));
          });
        });
      const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
      const pending = rpc.call(ACCOUNT, '0x' as Hex);
      // `call()` は最初の await（doFetch の結果待ち）に達するまで同期的に進むため、
      // ここで setTimeout の予約が既に捕捉されているはずである。
      expect(scheduled).toBeDefined();
      expect(scheduled?.ms).toBe(10_000);
      scheduled?.fn();
      await expect(pending).rejects.toMatchObject({
        code: ErrorCodes.CHAIN_SUBMIT_FAILED,
      });
    } finally {
      setTimeoutSpy.mockRestore();
    }
  });

  it('応答が返れば clearTimeout されタイマーが残らない', async () => {
    const clearTimeoutSpy = spyOn(globalThis, 'clearTimeout');
    try {
      const { fetch } = fetchReturning({ jsonrpc: '2.0', id: 1, result: OK_MAGIC });
      const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
      await rpc.call(ACCOUNT, '0xabcd' as Hex);
      expect(clearTimeoutSpy).toHaveBeenCalledTimes(1);
    } finally {
      clearTimeoutSpy.mockRestore();
    }
  });
});

/**
 * 双子（`aa/fetch-adapter.ts`）と同じ硬化。
 *
 * 以前の対策は aa 配下にしか当たらず、siwe 側は「本文上限なし / receiver 未束縛 / 本文未解放」の
 * 3 点を抱えたまま残った。往復を横断の `http/json-rpc.ts` に寄せたことで、3 点とも
 * ERC-1271 検証経路に効いていることを固定する。
 */
describe('createFetchErc1271Rpc: 硬化', () => {
  it('1 MiB を超える応答本文は 1021（content-length を宣言しない場合も実バイト数で打ち切る）', async () => {
    const oversized = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      result: `0x${'a'.repeat(1_048_576)}`,
    });
    const fetch: Erc1271FetchLike = () =>
      Promise.resolve(
        new Response(oversized, {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    await expect(rpc.call(ACCOUNT, '0x' as Hex)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
  });

  it('seam を裸で呼ばず、解決したレシーバを束ねて呼ぶ（this 参照つき実装が壊れない）', async () => {
    let seen: unknown = 'never-called';
    // メソッドとして定義された（= `this` を参照し得る）実装。裸呼び出しだと ESM は strict なので
    // `this` が undefined になり、`this.…` を読む実装は TypeError → 幻の 1021 になる。
    const source = {
      fetchImpl(this: unknown): Promise<Response> {
        seen = this;
        return Promise.resolve(
          new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: OK_MAGIC }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        );
      },
    };
    const rpc = createFetchErc1271Rpc('https://rpc.example', source.fetchImpl as Erc1271FetchLike);
    await rpc.call(ACCOUNT, '0x' as Hex);
    expect(seen).toBeDefined();
    expect((seen as { fetchImpl?: unknown }).fetchImpl).toBe(source.fetchImpl);
  });

  it('本文を読まずに失敗へ倒す経路でも応答本文を解放する', async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{}'));
      },
      cancel() {
        cancelled = true;
      },
    });
    const fetch: Erc1271FetchLike = () => Promise.resolve(new Response(body, { status: 500 }));
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    await expect(rpc.call(ACCOUNT, '0x' as Hex)).rejects.toMatchObject({
      code: ErrorCodes.CHAIN_SUBMIT_FAILED,
    });
    expect(cancelled).toBe(true);
  });
});

/**
 * `Object.prototype` 汚染。
 *
 * 往復を `http/json-rpc.ts` に寄せたことで、応答はパース境界（`parseJsonWithoutPrototype`）で
 * null-prototype 化される。`result` の鎖読みが復活すると、RPC が `{}` を返しただけで
 * `Object.prototype.result` の ERC-1271 マジックバリューが「チェーン上の検証結果」として通る。
 *
 * 非同期経路なので同期版フィクスチャは使えない（`await` の前に汚染が戻りトートロジーになる）。
 */
describe('createFetchErc1271Rpc: Object.prototype 汚染', () => {
  it('データ汚染: result を持たない応答で継承値を採用せず 1021', async () => {
    const { fetch } = fetchReturning({ jsonrpc: '2.0', id: 1 });
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    await withPollutedPrototypeAsync({ result: OK_MAGIC }, async () => {
      await expect(rpc.call(ACCOUNT, '0x' as Hex)).rejects.toMatchObject({
        code: ErrorCodes.CHAIN_SUBMIT_FAILED,
      });
    });
  });

  it('アクセサ汚染: result を持たない応答で継承値を採用せず 1021', async () => {
    const { fetch } = fetchReturning({ jsonrpc: '2.0', id: 1 });
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    await withPollutedPrototypeAccessorAsync({ result: () => OK_MAGIC }, async () => {
      await expect(rpc.call(ACCOUNT, '0x' as Hex)).rejects.toMatchObject({
        code: ErrorCodes.CHAIN_SUBMIT_FAILED,
      });
    });
  });

  it('データ汚染: error を持たない正常応答が汚染で失敗に落ちない（可用性）', async () => {
    const { fetch } = fetchReturning({ jsonrpc: '2.0', id: 1, result: OK_MAGIC });
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    const result = await withPollutedPrototypeAsync({ error: { code: -32000, message: 'x' } }, () =>
      rpc.call(ACCOUNT, '0x' as Hex),
    );
    expect(result).toBe(OK_MAGIC);
  });

  it('アクセサ汚染: error を持たない正常応答が汚染で失敗に落ちない（可用性）', async () => {
    const { fetch } = fetchReturning({ jsonrpc: '2.0', id: 1, result: OK_MAGIC });
    const rpc = createFetchErc1271Rpc('https://rpc.example', fetch);
    const result = await withPollutedPrototypeAccessorAsync(
      { error: () => ({ code: -32000, message: 'x' }) },
      () => rpc.call(ACCOUNT, '0x' as Hex),
    );
    expect(result).toBe(OK_MAGIC);
  });
});
