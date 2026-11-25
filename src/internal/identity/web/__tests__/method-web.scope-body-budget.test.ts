/**
 * 解決スコープ（VP 1 件 / `verifyDIDConfiguration` 1 回）全体の「取得・保持した本文量」の予算。
 *
 * `createBoundedResolver` の仕事量予算は署名検証・鍵ハッシュしか数えず、did:web は署名検証が無いため、
 * 1 MiB の `did.json` を返す相異なる did:web 32 件が `JSON.parse` され、スコープの間保持されて 1 GB 級の
 * ヒープになった。本文の文字数合計をスコープ共通の予算で数え、パースより前に `2001`（`resolution_work_limit`）で
 * 拒否する。実時間・RSS ではなく **`parseJsonWithoutPrototype` の呼び出し回数・fetch 回数・例外の種別**で pin し、
 * 本文サイズと件数の比率を変えた複数形状（少数の巨大 / 多数の極小 / 中間）で確認する。
 */

import { afterEach, describe, expect, it, spyOn } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import * as parseJsonModule from '../../../prototype-safety/parse-json.js';
import { createBoundedResolver, type DidResolverLike } from '../../bounded-resolver.js';
import { DEFAULT_MAX_SCOPE_BODY_LENGTH } from '../../resolution-budget.js';
import { Resolver } from '../../resolver.js';
import { resolveDidWebVh } from '../../webvh/method-webvh.js';
import { createDidWebCache } from '../did-web-cache.js';
import { MethodWeb } from '../method-web.js';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** ちょうど `length` 文字の did.json 本文（`x` に詰め物。DID Core 外のメンバーは許容される）。 */
function bodyOfLength(did: string, length: number): string {
  const head = `{"id":"${did}","x":"`;
  const tail = '"}';
  return `${head}${'a'.repeat(length - head.length - tail.length)}${tail}`;
}

interface Served {
  readonly dids: string[];
  readonly fetches: () => number;
}

/** `count` 個の相異なる did:web（各本文 `bodyLength` 文字）を返すグローバル `fetch` のモックを入れる。 */
function serveDocuments(count: number, bodyLength: number): Served {
  const dids = Array.from({ length: count }, (_, i) => `did:web:h${i}.example.com`);
  let fetches = 0;
  globalThis.fetch = (async (input: string | URL | Request) => {
    fetches += 1;
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const host = new URL(url).hostname;
    const response = new Response(bodyOfLength(`did:web:${host}`, bodyLength), {
      status: 200,
      headers: { 'content-type': 'application/did+json' },
    });
    Object.defineProperty(response, 'url', { value: url, configurable: true });
    return response;
  }) as unknown as typeof fetch;
  return { dids, fetches: () => fetches };
}

function scopedResolver(maxBodyLength?: number, web: MethodWeb = new MethodWeb()): DidResolverLike {
  const resolver = new Resolver();
  resolver.register(web);
  return createBoundedResolver(resolver, maxBodyLength === undefined ? {} : { maxBodyLength });
}

async function resolveSequentially(
  bounded: DidResolverLike,
  dids: readonly string[],
): Promise<PromiseSettledResult<unknown>[]> {
  const results: PromiseSettledResult<unknown>[] = [];
  for (const did of dids) {
    results.push(...(await Promise.allSettled([bounded.resolve(did)])));
  }
  return results;
}

function expectWorkLimit(result: PromiseSettledResult<unknown> | undefined): void {
  expect(result?.status).toBe('rejected');
  const reason = (result as PromiseRejectedResult).reason as VericertsError;
  expect(reason).toBeInstanceOf(VericertsError);
  expect(reason.code).toBe(ErrorCodes.INVALID_DID);
  expect(reason.context).toMatchObject({ reason: 'resolution_work_limit' });
}

describe('createBoundedResolver: スコープ全体の本文量（did:web）', () => {
  // [件数, 1 件の本文文字数, 予算]。どれも 1 件の上限（1 MiB）・件数の上限（32）には収まるが、合計は予算を超える。
  it.each([
    [32, 1_048_000, DEFAULT_MAX_SCOPE_BODY_LENGTH], // 少数の巨大要素（Issue の攻撃形状。4 件で打ち切り）
    [32, 65_536, 1_048_576], // 中間（64 KiB × 16 件でちょうど予算）
    [32, 1_000, 10_000], // 多数の極小要素（1,000 文字 × 10 件でちょうど予算）
  ])('%d 件 × %d 文字・予算 %d: パースは予算に収まる件数だけで止まる', async (count, length, budget) => {
    const { dids, fetches } = serveDocuments(count, length);
    const parse = spyOn(parseJsonModule, 'parseJsonWithoutPrototype');
    try {
      const results = await resolveSequentially(scopedResolver(budget), dids);
      const admitted = Math.floor(budget / length);
      expect(admitted).toBeLessThan(count);
      // 予算に収まる先頭の文書だけがパース・保持され、尽きた文書は **パースより前に** 2001 で拒否される。
      expect(parse).toHaveBeenCalledTimes(admitted);
      expect(results.slice(0, admitted).every((r) => r.status === 'fulfilled')).toBe(true);
      for (const result of results.slice(admitted)) {
        expectWorkLimit(result);
      }
      // 予算を使い切った（ちょうど 0 / 超過した本文を 1 件読んだ）時点で、以後の取得自体を始めない。
      expect(fetches()).toBe(budget - admitted * length > 0 ? admitted + 1 : admitted);
    } finally {
      parse.mockRestore();
    }
  });

  it('予算に収まる本文量なら 32 件すべて解決できる（正常系を壊さない）', async () => {
    const { dids } = serveDocuments(32, 2_000);
    const results = await resolveSequentially(scopedResolver(), dids);
    expect(results.every((r) => r.status === 'fulfilled')).toBe(true);
  });

  it('予算が尽きたスコープでは、後続の did:web を取得しない', async () => {
    const { dids, fetches } = serveDocuments(6, 1_000);
    const bounded = scopedResolver(2_500);
    const results = await resolveSequentially(bounded, dids);
    // 2 件を計上した時点で残りは 500 文字。3 件目は読んだ上で拒否され、スコープは使い切り扱いになる。
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(2);
    for (const result of results.slice(2)) {
      expectWorkLimit(result);
    }
    expect(fetches()).toBe(3);
  });

  it('本文量の残りが 0 になったスコープは、新しい did:web の取得自体を始めない', async () => {
    const { dids, fetches } = serveDocuments(4, 1_000);
    const bounded = scopedResolver(1_000);
    const results = await resolveSequentially(bounded, dids);
    expect(results[0]?.status).toBe('fulfilled');
    // 1 件目で残りがちょうど 0 になり、2 件目以降は fetch に出ない。
    for (const result of results.slice(1)) {
      expectWorkLimit(result);
    }
    expect(fetches()).toBe(1);
  });

  it('キャッシュヒットした文書もスコープへ同じ本文長を計上する', async () => {
    const { dids, fetches } = serveDocuments(3, 1_000);
    const web = new MethodWeb({ cache: createDidWebCache() });
    // 1 つ目のスコープでキャッシュへ載せる（取得で 1,000 文字を計上）。
    await resolveSequentially(scopedResolver(undefined, web), dids);
    expect(fetches()).toBe(3);
    // 2 つ目のスコープはすべて hot だが、保持する文書の本文長ぶんは予算から引かれる。
    const second = await resolveSequentially(scopedResolver(2_500, web), dids);
    expect(fetches()).toBe(3);
    expect(second.filter((r) => r.status === 'fulfilled')).toHaveLength(2);
    expectWorkLimit(second[2]);
  });

  it('スコープ外の単独解決（Resolver を直接使う）は本文量予算に影響されない', async () => {
    const { dids } = serveDocuments(8, 500_000);
    const resolver = new Resolver();
    resolver.register(new MethodWeb());
    for (const did of dids) {
      await expect(resolver.resolve(did)).resolves.toBeDefined();
    }
  });
});

describe('スコープ全体の本文量（did:webvh DID Log）', () => {
  /** 常に `body`（JSONL として不正な固定文字列）を返す fetch。 */
  function fetchReturning(body: string): typeof fetch {
    return (async () => {
      const response = new Response(body, {
        status: 200,
        headers: { 'content-type': 'application/jsonl' },
      });
      Object.defineProperty(response, 'url', {
        value: 'https://x.example.com/.well-known/did.jsonl',
        configurable: true,
      });
      return response;
    }) as unknown as typeof fetch;
  }

  const DID_VH = 'did:webvh:QmRTzGVeGa2BDhJ9MnrDdx1sLCbxj1R1aC4v5Ch2nVxDgr:x.example.com';

  it('DID Log の本文もパース・検証より前にスコープへ計上され、尽きれば 2001 で拒否される', async () => {
    const scope = { remaining: 1_000_000, remainingBodyLength: 500 };
    // 1 本目（400 文字）は予算内なので、本文の不正（チェーン検証）で別理由の 2001 になる。
    await expect(
      resolveDidWebVh(DID_VH, { fetchFn: fetchReturning('x'.repeat(400)) }, scope),
    ).rejects.not.toMatchObject({ context: { reason: 'resolution_work_limit' } });
    expect(scope.remainingBodyLength).toBe(100);
    // 2 本目は残り 100 文字に収まらず、本文を読んだ直後に resolution_work_limit で拒否される。
    await expect(
      resolveDidWebVh(DID_VH, { fetchFn: fetchReturning('x'.repeat(400)) }, scope),
    ).rejects.toMatchObject({
      code: ErrorCodes.INVALID_DID,
      context: { reason: 'resolution_work_limit' },
    });
    // 超過したスコープは使い切り扱いになり、以後の取得を始めさせない。
    expect(scope.remainingBodyLength).toBe(0);
  });
});
