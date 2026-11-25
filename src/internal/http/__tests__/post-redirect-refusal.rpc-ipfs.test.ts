/**
 * JSON-RPC POST と IPFS HTTP API POST が 3xx に追従しないことの回帰テスト。
 *
 * JSON-RPC（Bundler / Paymaster / ERC-1271）は署名済み UserOperation を、IPFS `key/import` は
 * IPNS の Ed25519 秘密鍵を本文で送る。307 / 308 に追従されると本文ごと Location へ再送されるため、
 * `redirect: 'manual'` で送り、3xx 応答は本文を読まずに失敗へ倒す。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { FetchLike } from '../../fetch-di.js';
import { ipfsAdd, ipfsKeyImport } from '../../identity/ipid/ipfs-api.js';
import { requestJsonRpc } from '../json-rpc.js';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

const LOCATION = 'https://10.0.0.5/steal';

interface Seen {
  readonly url: string;
  readonly redirect: RequestRedirect | undefined;
}

/** 常に 307 を返し、呼ばれた URL と `redirect` を記録するスタブ。 */
function redirecting(seen: Seen[]): FetchLike {
  return async (url, init) => {
    seen.push({ url, redirect: init.redirect });
    return new Response(null, { status: 307, headers: { Location: LOCATION } });
  };
}

/** `manual` が無視されて追従され、最終 URL が内部ホストになった 200 を返すスタブ。 */
function followedToInternal(): FetchLike {
  return async () => {
    const response = new Response('{"result":"0x1"}', { status: 200 });
    Object.defineProperty(response, 'url', { value: LOCATION });
    return response;
  };
}

const rpc = (url: string, fetchImpl: FetchLike) =>
  requestJsonRpc(url, fetchImpl, 1, 'eth_call', [], ErrorCodes.CHAIN_SUBMIT_FAILED);

describe('requestJsonRpc は 3xx に追従しない', () => {
  it.each([
    'https://bundler.example/rpc',
    'http://127.0.0.1:8545',
  ])('%s: redirect=manual で送り、307 は 2 ホップ目を呼ばず 1021 で失敗する', async (url) => {
    const seen: Seen[] = [];
    const caught = await rpc(url, redirecting(seen)).catch((error: unknown) => error);
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.CHAIN_SUBMIT_FAILED);
    expect(seen).toEqual([{ url, redirect: 'manual' }]);
  });

  it('追従されて最終 URL が内部ホストになった応答は採用しない', async () => {
    await expect(rpc('https://bundler.example/rpc', followedToInternal())).rejects.toMatchObject({
      name: 'VericertsError',
    });
  });

  it('リダイレクトしないループバック RPC は引き続き成功する', async () => {
    const fetchImpl: FetchLike = async () => new Response('{"result":"0x1"}', { status: 200 });
    expect(await rpc('http://127.0.0.1:8545', fetchImpl)).toBe('0x1');
  });
});

describe('IPFS HTTP API の POST は 3xx に追従しない', () => {
  const config = (apiUrl: string) => ({ gatewayUrl: 'https://ipfs.io', apiUrl });

  it.each([
    'https://kubo.example:5001',
    'http://127.0.0.1:5001',
  ])('%s: key/import は redirect=manual で送り、307 の Location へ鍵本文を再送しない', async (apiUrl) => {
    const seen: Seen[] = [];
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      seen.push({ url: String(input), redirect: init?.redirect });
      return new Response(null, { status: 307, headers: { Location: LOCATION } });
    }) as unknown as typeof fetch;

    const caught = await ipfsKeyImport(
      config(apiUrl),
      'persona-0',
      new Uint8Array(64).fill(9),
    ).catch((error: unknown) => error);
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.DID_NOT_FOUND);
    expect((caught as VericertsError).context).toEqual({ reason: 'insecure_api_url' });
    expect(seen).toHaveLength(1);
    expect(seen[0]?.redirect).toBe('manual');
    expect(seen[0]?.url).not.toBe(LOCATION);
  });

  it('追従されて最終 URL が内部ホストになった応答は採用しない', async () => {
    globalThis.fetch = (async () => {
      const response = new Response('{"Hash":"bafy"}', { status: 200 });
      Object.defineProperty(response, 'url', { value: LOCATION });
      return response;
    }) as unknown as typeof fetch;
    await expect(ipfsAdd(config('https://kubo.example:5001'), '{}')).rejects.toMatchObject({
      name: 'VericertsError',
    });
  });
});
