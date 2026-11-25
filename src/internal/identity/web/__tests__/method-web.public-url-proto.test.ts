/**
 * did:web / did:webvh 解決の取得シームと取得先の防御。
 *
 * - `Object.prototype` 汚染下で `deps = {}` / `options` 省略の解決が、汚染された `fetchFn` /
 *   `versionId` / キャッシュ設定を拾わない。
 * - 取得先がプライベート / ループバック宛、または公開ホストからのリダイレクト先がプライベート宛の
 *   場合は fetch せずに拒否する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import {
  generateKey,
  restoreFetch,
  signEntry,
  toJsonl,
} from '../../webvh/__tests__/webvh-fixtures.js';
import { createDidWebVh, resolveDidWebVh } from '../../webvh/method-webvh.js';
import { MethodWeb, resolveDidWeb } from '../method-web.js';

const DID = 'did:web:example.com';
const DOC = JSON.stringify({
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: DID,
  verificationMethod: [],
});

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  restoreFetch();
});

function jsonResponse(body: string, contentType = 'application/did+json'): Response {
  return new Response(body, { status: 200, headers: { 'content-type': contentType } });
}

/** 呼ばれた URL を記録する fetch ダブル。 */
function recordingFetch(handler: (url: string) => Response, seen: string[]): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input.toString();
    seen.push(url);
    return handler(url);
  }) as unknown as typeof fetch;
}

describe('取得シーム / 解決オプションの汚染耐性', () => {
  it('did:web: 継承した fetchFn / cache / nowSeconds / onCacheEvent を拾わず、グローバル fetch を使う', async () => {
    const attacker: string[] = [];
    const seen: string[] = [];
    globalThis.fetch = recordingFetch(() => jsonResponse(DOC), seen);
    const attackerFetch = recordingFetch(() => jsonResponse(DOC), attacker);
    const hits: string[] = [];
    const trap = (name: string) => () => {
      hits.push(name);
      return name === 'fetchFn' ? attackerFetch : undefined;
    };
    const doc = await withPollutedPrototypeAccessorAsync(
      {
        fetchFn: trap('fetchFn'),
        cache: trap('cache'),
        nowSeconds: trap('nowSeconds'),
        onCacheEvent: trap('onCacheEvent'),
        maxTtlSeconds: trap('maxTtlSeconds'),
      },
      async () => {
        const viaFn = await resolveDidWeb(DID);
        await new MethodWeb().resolve(DID);
        return viaFn;
      },
    );
    expect(doc.id).toBe(DID);
    expect(attacker).toEqual([]);
    expect(hits).toEqual([]);
    expect(seen.length).toBe(2);
  });

  it('did:webvh: 継承した fetchFn と versionId を拾わない', async () => {
    const key = generateKey();
    const vh = createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey] });
    const jsonl = toJsonl([signEntry(vh.logEntry, key)]);
    const attacker: string[] = [];
    const attackerFetch = recordingFetch(() => jsonResponse('', 'application/jsonl'), attacker);
    const polluted = { fetchFn: attackerFetch, versionId: '9-nonexistent' };

    globalThis.fetch = recordingFetch(() => jsonResponse(jsonl, 'application/jsonl'), []);
    const doc = await withPollutedPrototypeAsync(polluted, () => resolveDidWebVh(vh.did, {}));
    expect(doc.id).toBe(vh.did);
    expect(attacker).toEqual([]);
  });
});

describe('取得先 URL の公開ホスト検査', () => {
  it.each([
    'did:web:10.0.0.5',
    'did:web:127.0.0.1',
    'did:web:192.168.1.1',
    'did:web:localhost',
  ])('%s は fetch せず 2003 で拒否する', async (did) => {
    const seen: string[] = [];
    globalThis.fetch = recordingFetch(() => jsonResponse(DOC), seen);
    await expect(resolveDidWeb(did)).rejects.toMatchObject({ code: '2003' });
    expect(seen).toEqual([]);
  });

  it('did:web: 公開ホストからプライベート宛への 302 は追随せず 2003', async () => {
    const seen: string[] = [];
    globalThis.fetch = recordingFetch((url) => {
      if (url.startsWith('https://example.com')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://10.0.0.5/did.json' },
        });
      }
      return jsonResponse(DOC);
    }, seen);
    await expect(resolveDidWeb(DID)).rejects.toMatchObject({ code: '2003' });
    expect(seen).toEqual(['https://example.com/.well-known/did.json']);
  });

  it('did:web: 公開ホスト間のリダイレクトは追随して解決できる', async () => {
    const seen: string[] = [];
    globalThis.fetch = recordingFetch((url) => {
      if (url.startsWith('https://example.com')) {
        return new Response(null, {
          status: 301,
          headers: { location: 'https://cdn.example.org/did.json' },
        });
      }
      return jsonResponse(DOC);
    }, seen);
    const doc = await resolveDidWeb(DID);
    expect(doc.id).toBe(DID);
    expect(seen).toEqual([
      'https://example.com/.well-known/did.json',
      'https://cdn.example.org/did.json',
    ]);
  });

  it('did:webvh: IP リテラルの host は fetch せず 2001（仕様が IP を禁じる）、302 の内部宛も追随しない', async () => {
    const key = generateKey();
    const seen: string[] = [];
    globalThis.fetch = recordingFetch(() => jsonResponse('', 'application/jsonl'), seen);
    const scid = createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey] }).logEntry
      .parameters.scid as string;
    for (const host of ['192.168.1.1', '127%2E0%2E0%2E1', '0x7f.1', '2130706433']) {
      await expect(resolveDidWebVh(`did:webvh:${scid}:${host}`)).rejects.toMatchObject({
        code: '2001',
      });
    }
    expect(seen).toEqual([]);

    const pub = createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey] });
    globalThis.fetch = recordingFetch(
      () =>
        new Response(null, { status: 302, headers: { location: 'https://127.0.0.1/did.jsonl' } }),
      seen,
    );
    await expect(resolveDidWebVh(pub.did)).rejects.toMatchObject({ code: '2003' });
    expect(seen.length).toBe(1);
  });
});
