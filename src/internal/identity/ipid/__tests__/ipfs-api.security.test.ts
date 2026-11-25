/**
 * IPFS HTTP API 呼び出し（`ipfs-api.ts`）の入口検査の回帰テスト。
 *
 * `key/import` は IPNS の Ed25519 **秘密鍵そのもの**を `config.apiUrl` へ送る。`apiUrl` は
 * 呼び出し側が渡した任意の文字列なので、ループバックを出る平文 HTTP を許すと鍵が素のまま外へ出る。
 * したがって宛先が HTTPS でもループバックでもなければ **fetch を 1 度も発生させずに**拒否する。
 * あわせて、応答本文が `MAX_DOCUMENT_BYTES`（1 MiB）の内側で読まれること・呼び出しが
 * AbortSignal（タイムアウト）で覆われることを確かめる。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { MAX_DOCUMENT_BYTES } from '../../../http/body-limit.js';
import type { IpidGatewayConfig } from '../gateway.js';
import { ipfsAdd, ipfsKeyImport, ipfsNamePublish } from '../ipfs-api.js';

const CID = 'bafybeigdyrcreatedcid';
const KEY_NAME = 'persona-0';
/** libp2p Ed25519 秘密鍵の許容長（32〜68B）に収まるダミー鍵。 */
const KEY_BYTES = new Uint8Array(64).fill(9);

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

const config = (apiUrl: string): IpidGatewayConfig => ({ gatewayUrl: 'https://ipfs.io', apiUrl });

interface RecordedCall {
  readonly url: string;
  readonly signal: unknown;
}

/** 固定 JSON を返す fetch モック。呼び出しを記録する。 */
function mockApi(payload: Record<string, unknown>): RecordedCall[] {
  const calls: RecordedCall[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), signal: init?.signal });
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;
  return calls;
}

/** 本文をそのまま返す fetch モック（上限超過の検証用）。 */
function mockRawApi(body: string, headers?: Record<string, string>): void {
  globalThis.fetch = (async () =>
    new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/json', ...headers },
    })) as unknown as typeof fetch;
}

/** 呼ばれたら失敗させる fetch モック（送信そのものが起きないことの検証用）。 */
function forbidFetch(): void {
  globalThis.fetch = (() => {
    throw new Error('fetch must not be called');
  }) as unknown as typeof fetch;
}

describe('IPFS HTTP API の宛先スキーム検査', () => {
  it('ループバックを出る平文 apiUrl への key/import は送信せずに 2003 で拒否する', async () => {
    forbidFetch();
    let caught: VericertsError | undefined;
    try {
      await ipfsKeyImport(config('http://kubo.example:5001'), KEY_NAME, KEY_BYTES);
    } catch (error) {
      caught = error as VericertsError;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
    expect(caught?.context).toEqual({ reason: 'insecure_api_url' });
  });

  it('ループバックを出る平文 apiUrl への add / name publish も拒否する', async () => {
    forbidFetch();
    await expect(ipfsAdd(config('http://kubo.example:5001'), '{}')).rejects.toThrow(VericertsError);
    await expect(
      ipfsNamePublish(config('http://kubo.example:5001'), CID, KEY_NAME),
    ).rejects.toThrow(VericertsError);
  });

  it('HTTPS の apiUrl は受理する', async () => {
    const calls = mockApi({ Name: KEY_NAME });
    expect(await ipfsKeyImport(config('https://kubo.example:5001'), KEY_NAME, KEY_BYTES)).toBe(
      KEY_NAME,
    );
    expect(calls).toHaveLength(1);
  });

  it('ループバックの平文 apiUrl（既定の localhost 構成）は受理する', async () => {
    for (const apiUrl of ['http://localhost:5001', 'http://127.0.0.1:5001', 'http://[::1]:5001']) {
      const calls = mockApi({ Hash: CID });
      expect(await ipfsAdd(config(apiUrl), '{}')).toBe(CID);
      expect(calls).toHaveLength(1);
    }
  });

  it('URL として解釈できない apiUrl は拒否する', async () => {
    forbidFetch();
    await expect(ipfsAdd(config('not-a-url'), '{}')).rejects.toThrow(VericertsError);
  });
});

describe('IPFS HTTP API の応答本文とタイムアウト', () => {
  it('呼び出しは AbortSignal（タイムアウト）で覆われる', async () => {
    const calls = mockApi({ Hash: CID });
    await ipfsAdd(config('http://localhost:5001'), '{}');
    expect(calls[0]?.signal).toBeInstanceOf(AbortSignal);
  });

  it('MAX_DOCUMENT_BYTES を超える応答本文は 2003 で拒否する', async () => {
    mockRawApi(`"${'a'.repeat(MAX_DOCUMENT_BYTES)}"`);
    let caught: VericertsError | undefined;
    try {
      await ipfsAdd(config('http://localhost:5001'), '{}');
    } catch (error) {
      caught = error as VericertsError;
    }
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
    expect(caught?.context).toEqual({ reason: 'oversized_body' });
  });

  it('content-length が上限超過を宣言する応答は本文を読む前に拒否する', async () => {
    mockRawApi('{}', { 'content-length': String(MAX_DOCUMENT_BYTES + 1) });
    let caught: VericertsError | undefined;
    try {
      await ipfsAdd(config('http://localhost:5001'), '{}');
    } catch (error) {
      caught = error as VericertsError;
    }
    expect(caught?.context).toEqual({ reason: 'oversized_body' });
  });
});

// 回帰テスト: `ipfsApiUrl` が平文 http で許すループバックは `localhost` / `127.0.0.1` / `[::1]` の
// 3 つだけ。以前は `127.0.0.0/8` 全体（`127.0.0.2` など）を通していた。
describe('IPFS HTTP API のループバックは 3 つだけ', () => {
  it.each([
    'http://127.0.0.2:5001',
    'http://127.1.2.3:5001',
    'http://127.0.0.0:5001',
    'http://127.255.255.254:5001',
  ])('127.0.0.1 以外の 127.0.0.0/8 への key/import は送信せずに 2003 で拒否する: %s', async (apiUrl) => {
    forbidFetch();
    let caught: VericertsError | undefined;
    try {
      await ipfsKeyImport(config(apiUrl), KEY_NAME, KEY_BYTES);
    } catch (error) {
      caught = error as VericertsError;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect(caught?.code).toBe(ErrorCodes.DID_NOT_FOUND);
    expect(caught?.context).toEqual({ reason: 'insecure_api_url' });
  });

  // 3 つに「見える」だけの host は別ホストなので、add / name publish も含めて送信せずに拒否する。
  it.each([
    'http://localhost.:5001',
    'http://foo.localhost:5001',
    'http://[::ffff:127.0.0.1]:5001',
    'http://localhost@evil.example:5001',
    'http://127.0.0.1.evil.example:5001',
  ])('3 つに見えるだけの host は送信せずに 2003 で拒否する: %s', async (apiUrl) => {
    forbidFetch();
    for (const call of [
      () => ipfsAdd(config(apiUrl), '{}'),
      () => ipfsNamePublish(config(apiUrl), CID, KEY_NAME),
    ]) {
      await expect(call()).rejects.toMatchObject({
        code: ErrorCodes.DID_NOT_FOUND,
        context: { reason: 'insecure_api_url' },
      });
    }
  });

  // `new URL()` が同じホストへ正規化する書き方は 3 つのいずれかと同じなので通る。
  it.each([
    'http://localhost:5001',
    'http://127.0.0.1:5001',
    'http://[::1]:5001',
    'http://LOCALHOST:5001',
    'http://127.1:5001',
    'http://[0:0:0:0:0:0:0:1]:5001',
    'http://0x7f.1:5001',
  ])('3 つ（と同じ host に正規化される書き方）は受理する: %s', async (apiUrl) => {
    const calls = mockApi({ Hash: CID });
    expect(await ipfsAdd(config(apiUrl), '{}')).toBe(CID);
    expect(calls).toHaveLength(1);
  });
});
