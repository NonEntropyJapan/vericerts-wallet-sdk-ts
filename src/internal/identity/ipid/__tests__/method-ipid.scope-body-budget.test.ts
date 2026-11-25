/**
 * did:ipid の解決も、解決スコープ全体の「取得・保持した本文量」の予算を計上する。
 *
 * 以前の did:ipid は `scope` を受け取らず、1 MiB の `did.json` を返す相異なる did:ipid 32 件で署名検証前に
 * RSS 1 GB・CPU 3.7 秒を使えた（did:web は 5 件で打ち切り）。実時間ではなく、成功件数・Gateway への
 * 要求回数・例外の種別で pin する。サイズと件数の比率を変えた複数形状で確かめる。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { createBoundedResolver } from '../../bounded-resolver.js';
import { DEFAULT_MAX_SCOPE_BODY_LENGTH } from '../../resolution-budget.js';
import { MethodIpid } from '../method-ipid.js';
import { ipnsNameOf, rawCidOf } from './cid-fixture.js';
import { ipnsRecordOf } from './ipns-fixture.js';

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

/** ちょうど `length` 文字の did.json（`id` 付き。`x` に詰め物）。 */
function bodyOfLength(did: string, length: number): string {
  const head = `{"id":"${did}","x":"`;
  const tail = '"}';
  return `${head}${'a'.repeat(length - head.length - tail.length)}${tail}`;
}

/** Gateway が `bodies[path]` を返し、取得した path を記録するモック（`/ipns/` は署名付きレコード）。 */
function serveGateway(bodies: Map<string, string | Uint8Array<ArrayBuffer>>): string[] {
  const requested: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
    requested.push(path);
    const body = bodies.get(path);
    if (body === undefined) {
      return new Response('', { status: 404 });
    }
    const contentType = path.startsWith('/ipns/')
      ? 'application/vnd.ipfs.ipns-record'
      : 'application/json';
    return new Response(body, { status: 200, headers: { 'content-type': contentType } });
  }) as unknown as typeof fetch;
  return requested;
}

/** 相異なる did:ipid（IPNS 名）`count` 件を、それぞれ `bodyLength` 文字の本文で配信する（署名付きレコード経由）。 */
function ipnsDids(count: number, bodyLength: number): { dids: string[]; requested: string[] } {
  const bodies = new Map<string, string | Uint8Array<ArrayBuffer>>();
  const dids: string[] = [];
  for (let i = 0; i < count; i++) {
    const did = `did:ipid:${ipnsNameOf(i + 1)}`;
    dids.push(did);
    const body = bodyOfLength(did, bodyLength);
    const cid = rawCidOf(body);
    bodies.set(`/ipns/${ipnsNameOf(i + 1)}`, ipnsRecordOf(i + 1, cid));
    bodies.set(`/ipfs/${cid}`, body);
  }
  return { dids, requested: serveGateway(bodies) };
}

async function settleAll(
  resolve: (did: string) => Promise<unknown>,
  dids: readonly string[],
): Promise<PromiseSettledResult<unknown>[]> {
  const results: PromiseSettledResult<unknown>[] = [];
  for (const did of dids) {
    results.push((await Promise.allSettled([resolve(did)]))[0] as PromiseSettledResult<unknown>);
  }
  return results;
}

function expectWorkLimit(result: PromiseSettledResult<unknown> | undefined): void {
  expect(result?.status).toBe('rejected');
  const error = (result as PromiseRejectedResult).reason as VericertsError;
  expect(error.code).toBe(ErrorCodes.INVALID_DID);
  expect(error.context?.reason).toBe('resolution_work_limit');
}

describe('did:ipid: 解決スコープの本文量予算', () => {
  // 総量 = count × bodyLength を 4 MiB の前後にまたがせた形状（1 件の大きさと件数の比率を変える）。
  const shapes = [
    ['1 MiB × 32 件（攻撃形状）', 32, 1024 * 1024],
    ['512 KiB × 32 件', 32, 512 * 1024],
    ['128 KiB × 40 件ぶん（上限は 32 件）', 32, 256 * 1024],
  ] as const;

  it.each(shapes)('%s: 予算を超えた解決を fail-closed にする', async (_name, count, bodyLength) => {
    const { dids } = ipnsDids(count, bodyLength);
    const resolver = createBoundedResolver(new MethodIpid());
    const results = await settleAll((did) => resolver.resolve(did), dids);

    const admitted = Math.floor(DEFAULT_MAX_SCOPE_BODY_LENGTH / bodyLength);
    const fulfilled = results.filter((r) => r.status === 'fulfilled').length;
    // 取得した本文は計上されるので、予算が許す件数（文書の id 補完・区切りぶんの誤差で 1 件以内）に収まる。
    expect(fulfilled).toBeLessThanOrEqual(admitted);
    expect(fulfilled).toBeGreaterThanOrEqual(admitted - 1);
    expectWorkLimit(results[admitted]);
    expectWorkLimit(results[count - 1]);
  });

  it('予算が尽きたスコープでは Gateway へ取得自体を送らない', async () => {
    const { dids, requested } = ipnsDids(32, 1024 * 1024);
    const resolver = createBoundedResolver(new MethodIpid());
    await settleAll((did) => resolver.resolve(did), dids);

    // 4 MiB ぶん（約 4 件）を読んだ時点で打ち切り、以降の DID は要求を送らない。IPNS 名は 1 件あたり
    // レコード取得と本文取得の 2 要求になる。
    const requestsPerDid = 2;
    expect(requested.length).toBeLessThanOrEqual(
      requestsPerDid * (DEFAULT_MAX_SCOPE_BODY_LENGTH / (1024 * 1024) + 1),
    );
  });

  it('CID 形式（イミュータブル）の did:ipid も同じ予算で縛る（CID 照合・パースより前）', async () => {
    const bodies = new Map<string, string>();
    const dids: string[] = [];
    for (let i = 0; i < 12; i++) {
      // 本文の CID は本文自身から決まる。id を持たない形（canonical）にして CID を自己整合させる。
      const prefix = `{"x":"${i}`;
      const canonical = `${prefix}${'a'.repeat(1024 * 1024 - prefix.length - 2)}"}`;
      const cid = rawCidOf(canonical);
      bodies.set(`/ipfs/${cid}`, canonical);
      dids.push(`did:ipid:${cid}`);
    }
    serveGateway(bodies);
    const resolver = createBoundedResolver(new MethodIpid());
    const results = await settleAll((did) => resolver.resolve(did), dids);
    const fulfilled = results.filter((r) => r.status === 'fulfilled').length;
    expect(fulfilled).toBeLessThanOrEqual(4);
    expect(fulfilled).toBeGreaterThanOrEqual(3);
    expectWorkLimit(results[11]);
  });

  it('予算内の通常サイズの did:ipid は 32 件すべて解決できる（正常系を壊さない）', async () => {
    const { dids } = ipnsDids(32, 2048);
    const resolver = createBoundedResolver(new MethodIpid());
    const results = await settleAll((did) => resolver.resolve(did), dids);
    expect(results.every((r) => r.status === 'fulfilled')).toBe(true);
  });

  it('スコープ無しの単独解決（`MethodIpid.resolve(did)`）は従来どおり計上しない', async () => {
    const { dids } = ipnsDids(6, 1024 * 1024);
    const method = new MethodIpid();
    for (const did of dids) {
      await expect(method.resolve(did)).resolves.toBeDefined();
    }
  });
});
