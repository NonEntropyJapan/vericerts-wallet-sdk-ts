/**
 * 公開 API `createDidResolver`（DID メソッド一式を登録した Resolver を Wallet なしで構築する）の配線テスト。
 *
 * 判定方法は `wallet.resolve-methods.test.ts` と同じ: 登録済みメソッドに不正な識別子を渡すとそのメソッドが
 * `2001` 等で reject する（`2002` にならない）。未登録メソッドは Resolver が `2002` で reject する。
 * 接続先（RPC / Gateway）はグローバル `fetch` を差し替えて、送出先 URL で観測する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAccessorAsync } from '../../../internal/__tests__/prototype-pollution.fixtures.js';
import { VericertsError } from '../../../internal/errors.js';
import { MemoryStorage } from '../../../storage/storage.js';
import { createDidResolver, type DidResolverOptions } from '../../did/did-resolver.js';
import { createWallet } from '../../factory.js';

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

const ETHR_ADDRESS = '0x1111111111111111111111111111111111111111';
const IPID_CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';

/** `fetch` を差し替え、送出先 URL を記録する。`respond` を省略すると全要求を 404 にする。 */
function stubFetch(respond?: (url: string) => Response): string[] {
  const urls: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    urls.push(url);
    return respond === undefined ? new Response('', { status: 404 }) : respond(url);
  }) as typeof fetch;
  return urls;
}

/** `eth_getLogs` に「イベントなし」を返す RPC。 */
function emptyLogsRpc(): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: [] }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function resolveErrorCode(did: string, options?: DidResolverOptions): Promise<string | null> {
  try {
    await createDidResolver(options).resolve(did);
    return null;
  } catch (error) {
    if (error instanceof VericertsError) return error.code;
    throw error;
  }
}

describe('createDidResolver: 登録メソッド', () => {
  it.each([
    'key',
    'jwk',
    'peer',
    'jwt',
    'pkh',
    'ethr',
    'web',
    'webvh',
    'ipid',
    'plc',
  ])('did:%s は既定で登録済み（未対応 2002 にならない）', async (method) => {
    stubFetch();
    expect(await resolveErrorCode(`did:${method}:`)).not.toBe('2002');
  });

  it.each([
    'ebsi',
    'ion',
    'cheqd',
  ])('did:%s はノード URL 未指定なら未登録で 2002', async (method) => {
    expect(await resolveErrorCode(`did:${method}:example`)).toBe('2002');
  });

  it('did:ebsi / ion / cheqd は didNodeUrls で当該 URL を渡したメソッドだけが登録される', async () => {
    stubFetch();
    const options = { didNodeUrls: { ebsi: 'https://ebsi.example' } };
    expect(await resolveErrorCode('did:ebsi:z', options)).not.toBe('2002');
    expect(await resolveErrorCode('did:ion:abc', options)).toBe('2002');
    expect(await resolveErrorCode('did:cheqd:mainnet:abc', options)).toBe('2002');
  });

  it('did:tdw は未登録（2002）', async () => {
    expect(await resolveErrorCode('did:tdw:QmScid:example.com')).toBe('2002');
  });

  it('did:key は fetch を使わず解決できる', async () => {
    const urls = stubFetch();
    const document = await createDidResolver().resolve(
      'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    );
    expect(document.id).toBe('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    expect(urls).toEqual([]);
  });
});

describe('createDidResolver: did:ethr の RPC（rpcUrls）', () => {
  it('rpcUrls に載せたチェーンはその RPC URL へ問い合わせて解決する', async () => {
    const urls = stubFetch(emptyLogsRpc);
    const document = await createDidResolver({
      rpcUrls: { 1: 'https://rpc.example/mainnet' },
    }).resolve(`did:ethr:${ETHR_ADDRESS}`);
    expect(document.id).toBe(`did:ethr:${ETHR_ADDRESS}`);
    expect(urls.length).toBeGreaterThan(0);
    expect(new Set(urls)).toEqual(new Set(['https://rpc.example/mainnet']));
  });

  it('rpcUrls に無いチェーンは接続せず DID_NOT_FOUND（2003、fail-closed）', async () => {
    const urls = stubFetch(emptyLogsRpc);
    const options = { rpcUrls: { 1: 'https://rpc.example/mainnet' } };
    expect(await resolveErrorCode(`did:ethr:42161:${ETHR_ADDRESS}`, options)).toBe('2003');
    expect(await resolveErrorCode(`did:ethr:${ETHR_ADDRESS}`, undefined)).toBe('2003');
    expect(urls).toEqual([]);
  });

  it('RPC が到達不能・非 2xx なら DID_NOT_FOUND（2003）', async () => {
    stubFetch();
    expect(
      await resolveErrorCode(`did:ethr:${ETHR_ADDRESS}`, { rpcUrls: { 1: 'https://rpc.example' } }),
    ).toBe('2003');
  });
});

describe('createDidResolver: did:ipid の Gateway（ipfsGatewayUrl）', () => {
  it('省略時は既定 Gateway（https://ipfs.io）へ問い合わせる', async () => {
    const urls = stubFetch();
    expect(await resolveErrorCode(`did:ipid:${IPID_CID}`)).toBe('2003');
    expect(urls).toEqual([`https://ipfs.io/ipfs/${IPID_CID}`]);
  });

  it('ipfsGatewayUrl を渡すとその Gateway へ問い合わせる', async () => {
    const urls = stubFetch();
    expect(
      await resolveErrorCode(`did:ipid:${IPID_CID}`, { ipfsGatewayUrl: 'https://gw.example/' }),
    ).toBe('2003');
    expect(urls).toEqual([`https://gw.example/ipfs/${IPID_CID}`]);
  });
});

describe('createDidResolver: 呼び出しオプションは own 限定で読む', () => {
  it('省略した rpcUrls / ipfsGatewayUrl / ipfsApiUrl / didNodeUrls を継承値から読まない', async () => {
    const read: string[] = [];
    const getters = Object.fromEntries(
      ['rpcUrls', 'ipfsGatewayUrl', 'ipfsApiUrl', 'didNodeUrls'].map((key) => [
        key,
        () => {
          read.push(key);
          return undefined;
        },
      ]),
    );
    await withPollutedPrototypeAccessorAsync(getters, async () => {
      createDidResolver({});
    });
    expect(read).toEqual([]);
  });

  it('汚染された Object.prototype.rpcUrls は未設定チェーンの接続先にならない', async () => {
    const urls = stubFetch(emptyLogsRpc);
    await withPollutedPrototypeAccessorAsync(
      { rpcUrls: () => ({ 1: 'https://attacker.example' }) },
      async () => {
        expect(await resolveErrorCode(`did:ethr:${ETHR_ADDRESS}`, {})).toBe('2003');
      },
    );
    expect(urls).toEqual([]);
  });
});

describe('createDidResolver と createWallet は同じ DID メソッド一式を登録する', () => {
  it.each([
    'did:key:',
    'did:jwk:',
    'did:peer:',
    'did:jwt:',
    'did:pkh:',
    'did:ethr:',
    'did:web:',
    'did:webvh:',
    'did:ipid:',
    'did:plc:',
    'did:ebsi:x',
    'did:ion:x',
    'did:cheqd:x',
    'did:tdw:x',
    'did:unknown:x',
  ])('%s の登録有無（2002 か否か）が一致する', async (did) => {
    stubFetch();
    const wallet = await createWallet({ storage: new MemoryStorage() });
    let walletCode: string | null = null;
    try {
      await wallet.resolveDID(did);
    } catch (error) {
      walletCode = error instanceof VericertsError ? error.code : null;
    }
    expect(walletCode === '2002').toBe((await resolveErrorCode(did)) === '2002');
  });
});
