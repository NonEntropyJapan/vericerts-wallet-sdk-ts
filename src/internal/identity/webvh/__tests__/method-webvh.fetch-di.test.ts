/**
 * did:webvh 解決の fetch DI seam の回帰テスト。
 *
 * `fetchDidLog` は「ホストアプリが証明書ピン留め済みの `fetch` を注入できるようにするための seam」
 * として第 2 引数を持つが、`resolveDidWebVh` がそれを渡さないあいだ seam は
 * 本番経路から到達できず、did:webvh だけがグローバル `fetch` へ素通りしていた。注入した `fetch`
 * が実際に使われ、グローバル `fetch` が呼ばれないことを固定する（did:web の
 * `ResolveDidWebDeps.fetchFn` と同形）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { createDidWebVh, parseWebVh, resolveDidWebVh, webVhLogUrl } from '../method-webvh.js';
import { generateKey, restoreFetch, signEntry, toJsonl } from './webvh-fixtures.js';

afterEach(() => {
  restoreFetch();
});

/** 初版のみの署名済み DID Log を作る。 */
function buildGenesisLog(): { did: string; jsonl: string } {
  const key = generateKey();
  const { did, logEntry } = createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey] });
  return { did, jsonl: toJsonl([signEntry(logEntry, key)]) };
}

/** グローバル `fetch` を「呼ばれたら失敗」に差し替える。 */
function forbidGlobalFetch(): void {
  globalThis.fetch = (() => {
    throw new Error('global fetch must not be used');
  }) as unknown as typeof fetch;
}

/** DID Log を返す `fetch` ダブル（受け取った URL を記録する）。 */
function injectedFetch(jsonl: string, seen: string[]): typeof fetch {
  return (async (input: string | URL | Request) => {
    seen.push(typeof input === 'string' ? input : input.toString());
    return new Response(jsonl, { status: 200, headers: { 'content-type': 'application/jsonl' } });
  }) as unknown as typeof fetch;
}

describe('resolveDidWebVh の fetch DI seam', () => {
  it('`options.fetchFn` を DID Log 取得に使い、グローバル `fetch` を呼ばない', async () => {
    const { did, jsonl } = buildGenesisLog();
    forbidGlobalFetch();
    const seen: string[] = [];

    const doc = await resolveDidWebVh(did, { fetchFn: injectedFetch(jsonl, seen) });

    expect(doc.id).toBe(did);
    expect(seen).toEqual([webVhLogUrl(parseWebVh(did))]);
  });

  it('`fetchFn` 未指定ならグローバル `fetch` を使う（既定は据え置き）', async () => {
    const { did, jsonl } = buildGenesisLog();
    const seen: string[] = [];
    globalThis.fetch = injectedFetch(jsonl, seen);

    const doc = await resolveDidWebVh(did);

    expect(doc.id).toBe(did);
    expect(seen).toEqual([webVhLogUrl(parseWebVh(did))]);
  });
});
