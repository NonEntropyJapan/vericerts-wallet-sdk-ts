/**
 * createFetchPaymasterClient（fetch ベース PaymasterClient 既定実装、ERC-7677）のユニットテスト。
 *
 * fetch を注入し実ネットワーク非依存で検証する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../fetch-adapter.js';
import { createFetchPaymasterClient } from '../../paymaster-fetch-adapter.js';
import { ENTRY_POINT_V07_ADDRESS, type Hex, type UserOperationV07 } from '../../types.js';

const URL = 'https://paymaster.example/rpc';
const SENDER = '0x1111111111111111111111111111111111111111' as Hex;
const PAYMASTER = '0x2222222222222222222222222222222222222222' as Hex;

const OP: UserOperationV07 = {
  sender: SENDER,
  nonce: 5n,
  callData: '0xabcdef' as Hex,
  callGasLimit: 100_000n,
  verificationGasLimit: 200_000n,
  preVerificationGas: 50_000n,
  maxFeePerGas: 1_000_000_000n,
  maxPriorityFeePerGas: 900_000_000n,
  signature: '0x' as Hex,
};

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

const OK_RESULT = {
  paymaster: PAYMASTER,
  paymasterData: '0xdead',
  paymasterVerificationGasLimit: '0x7530',
  paymasterPostOpGasLimit: '0x2710',
};

describe('createFetchPaymasterClient', () => {
  test('getPaymasterData は pm_getPaymasterData を hexlified UserOp・EntryPoint・chainId で呼ぶ', async () => {
    const { fetch, bodies } = fakeFetch(() => ({ json: { result: OK_RESULT } }));
    const client = createFetchPaymasterClient(URL, fetch);
    const fields = await client.getPaymasterData(OP, 137);
    expect(fields.paymaster).toBe(PAYMASTER);
    expect(fields.paymasterData).toBe('0xdead');
    expect(fields.paymasterVerificationGasLimit).toBe(30_000n);
    expect(fields.paymasterPostOpGasLimit).toBe(10_000n);

    const sent = bodies[0] as Record<string, unknown>;
    expect(sent.method).toBe('pm_getPaymasterData');
    const params = sent.params as unknown[];
    expect((params[0] as Record<string, string>).nonce).toBe('0x5');
    expect(params[1]).toBe(ENTRY_POINT_V07_ADDRESS);
    expect(params[2]).toBe('0x89'); // chainId 137 hex
  });

  test('getPaymasterStubData は pm_getPaymasterStubData を呼ぶ', async () => {
    const { fetch, bodies } = fakeFetch(() => ({ json: { result: OK_RESULT } }));
    const client = createFetchPaymasterClient(URL, fetch);
    await client.getPaymasterStubData(OP, 1);
    const sent = bodies[0] as Record<string, unknown>;
    expect(sent.method).toBe('pm_getPaymasterStubData');
    expect((sent.params as unknown[])[2]).toBe('0x1');
  });

  test('リクエスト ID を連番でインクリメントする', async () => {
    const { fetch, bodies } = fakeFetch(() => ({ json: { result: OK_RESULT } }));
    const client = createFetchPaymasterClient(URL, fetch);
    await client.getPaymasterStubData(OP, 1);
    await client.getPaymasterData(OP, 1);
    expect((bodies[0] as Record<string, unknown>).id).toBe(1);
    expect((bodies[1] as Record<string, unknown>).id).toBe(2);
  });

  test('Paymaster の JSON-RPC error は 7003 PAYMASTER_REJECTED に正規化し本文を伝播しない', async () => {
    const { fetch } = fakeFetch(() => ({
      json: { error: { code: -32000, message: 'secret 0xdeadbeef reason' } },
    }));
    const client = createFetchPaymasterClient(URL, fetch);
    try {
      await client.getPaymasterData(OP, 1);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(VericertsError);
      expect((e as VericertsError).code).toBe('7003');
      expect((e as VericertsError).message).not.toContain('secret');
      expect((e as VericertsError).cause).toBeUndefined();
    }
  });

  test('HTTP 非 200 は 1021', async () => {
    const { fetch } = fakeFetch(() => ({ ok: false, json: {} }));
    const client = createFetchPaymasterClient(URL, fetch);
    await expect(client.getPaymasterData(OP, 1)).rejects.toThrow(VericertsError);
  });

  test('トランスポート例外は 1021 に正規化し本文を伝播しない', async () => {
    const fetch: FetchLike = async () => {
      throw new Error('ECONNREFUSED 10.0.0.1');
    };
    const client = createFetchPaymasterClient(URL, fetch);
    try {
      await client.getPaymasterData(OP, 1);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as VericertsError).code).toBe('1021');
      expect((e as VericertsError).message).not.toContain('10.0.0.1');
    }
  });
});

/**
 * Bundler 経路と同じ硬化が Paymaster 経路にも効いていること。
 *
 * 判定そのものは fetch-adapter.ts の `requestJsonRpc` に 1 か所だけ置いてあるので、ここでは
 * 「この経路がその共有実装を通っているか」だけを押さえる（詳細は fetch-adapter.test.ts）。
 */
describe('createFetchPaymasterClient: 硬化', () => {
  test('seam に AbortSignal を渡す（応答を返さない相手を abort できる）', async () => {
    let signal: AbortSignal | undefined;
    const fetch: FetchLike = (_url, init) => {
      signal = init.signal;
      return Promise.resolve(
        new Response(JSON.stringify({ result: OK_RESULT }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    };
    await createFetchPaymasterClient(URL, fetch).getPaymasterData(OP, 1);
    expect(signal).toBeInstanceOf(AbortSignal);
  });

  test('1 MiB を超える応答本文は 1021', async () => {
    const fetch: FetchLike = () =>
      Promise.resolve(
        new Response(JSON.stringify({ result: { paymasterData: `0x${'a'.repeat(1_048_576)}` } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    await expect(
      createFetchPaymasterClient(URL, fetch).getPaymasterData(OP, 1),
    ).rejects.toMatchObject({ code: ErrorCodes.CHAIN_SUBMIT_FAILED });
  });
});
