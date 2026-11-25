/**
 * did:ethr の解決も、解決スコープ全体の予算（仕事量・本文量）を計上する。
 *
 * 以前の did:ethr は `scope` を受け取らず、各 990 件のイベントを持つ相異なる did:ethr 32 件の解決が
 * 署名検証前に 3.4 秒・CPU 4.0 秒を使えた。ログのデコード前に「ログの保持量」と「デコード仕事量」を
 * スコープへ計上する。実時間ではなく、成功件数・RPC 往復回数・例外の種別で pin する。
 * イベント数と DID 数の比率を変えた複数形状で確かめる。
 */

import { describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../__tests__/heavy-input-timeout.js';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { createBoundedResolver } from '../../bounded-resolver.js';
import {
  DEFAULT_MAX_SCOPE_BODY_LENGTH,
  DEFAULT_MAX_SCOPE_WORK_UNITS,
  WORK_UNITS_PER_EVENT_DECODE,
} from '../../resolution-budget.js';
import { estimateJsonLength } from '../../resolution-charge.js';
import { MethodEthr } from '../method-ethr.js';
import { attributeLog, CHAIN_ID, type LogsFor, RPC_URL, rpcStub, toBytes32 } from './rpc-stub.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

const NAME = toBytes32('did/svc/Svc');

function attributeLogs(count: number, identity?: string): unknown[] {
  return Array.from({ length: count }, (_, i) => attributeLog(NAME, '0x01', 1, 1 + i, 0, identity));
}

/** 要求の identity topic（32 バイト左ゼロ詰め）に対応する、そのアドレスのログだけを返す（別 identity のログは 2003 になる）。 */
function attributeLogsFor(count: number): LogsFor {
  return (identityTopic) => attributeLogs(count, `0x${identityTopic.slice(26)}`);
}

/** 相異なる did:ethr アドレス（20 バイト）。 */
function ethrDid(index: number): string {
  return `did:ethr:0x${(index + 1).toString(16).padStart(40, '0')}`;
}

function scopedResolver(eventsPerDid: number) {
  // 本文量の見積り用（identity 以外は同形・同サイズ）。応答は DID ごとの identity で作る。
  const logs = attributeLogs(eventsPerDid);
  const stub = rpcStub({ attribute: attributeLogsFor(eventsPerDid) });
  const method = new MethodEthr({
    rpcUrls: { [CHAIN_ID]: RPC_URL },
    fetchImpl: stub.fetchImpl,
  });
  return { resolver: createBoundedResolver(method), stub, logs };
}

async function settleAll(
  resolve: (did: string) => Promise<unknown>,
  count: number,
): Promise<PromiseSettledResult<unknown>[]> {
  const results: PromiseSettledResult<unknown>[] = [];
  for (let i = 0; i < count; i++) {
    results.push(
      (await Promise.allSettled([resolve(ethrDid(i))]))[0] as PromiseSettledResult<unknown>,
    );
  }
  return results;
}

function expectWorkLimit(result: PromiseSettledResult<unknown> | undefined): void {
  expect(result?.status).toBe('rejected');
  const error = (result as PromiseRejectedResult).reason as VericertsError;
  expect(error.code).toBe(ErrorCodes.INVALID_DID);
  expect(error.context?.reason).toBe('resolution_work_limit');
}

describe('did:ethr: 解決スコープの予算', () => {
  // [イベント数 / DID, DID 数]。総量の比率を変えて、仕事量予算・本文量予算のどちらが先に尽きる形も含める。
  const shapes = [
    [990, 32],
    [500, 32],
    [200, 32],
    [50, 32],
  ] as const;

  it.each(
    shapes,
  )('1 DID あたり %d イベント × %d DID: 予算を超えた解決を fail-closed にする', async (events, count) => {
    const { resolver, stub, logs } = scopedResolver(events);
    const results = await settleAll((did) => resolver.resolve(did), count);

    const byWork = Math.floor(
      DEFAULT_MAX_SCOPE_WORK_UNITS / (events * WORK_UNITS_PER_EVENT_DECODE),
    );
    const logLength = estimateJsonLength([[], logs], Number.MAX_SAFE_INTEGER);
    const byBody = Math.floor(DEFAULT_MAX_SCOPE_BODY_LENGTH / logLength);
    const admitted = Math.min(byWork, byBody, count);

    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(admitted);
    if (admitted < count) {
      expectWorkLimit(results[admitted]);
      expectWorkLimit(results[count - 1]);
      // 予算が尽きたスコープでは RPC へも出ない（owner / attribute の 2 クエリ × 解決を始めた DID 数）。
      expect(stub.requests.length).toBeLessThanOrEqual((admitted + 1) * 2);
    }
  });

  it('攻撃形状（990 イベント × 32 DID）では、成功は 32 件のうち数件に打ち切られる', async () => {
    const { resolver } = scopedResolver(990);
    const results = await settleAll((did) => resolver.resolve(did), 32);
    const fulfilled = results.filter((r) => r.status === 'fulfilled').length;
    expect(fulfilled).toBeGreaterThanOrEqual(1);
    expect(fulfilled).toBeLessThanOrEqual(10);
  });

  it('予算内の通常サイズの did:ethr は 32 件すべて解決できる（正常系を壊さない）', async () => {
    const { resolver } = scopedResolver(3);
    const results = await settleAll((did) => resolver.resolve(did), 32);
    expect(results.every((r) => r.status === 'fulfilled')).toBe(true);
  });

  it('スコープ無しの単独解決（`MethodEthr.resolve(did)`）は従来どおり計上しない', async () => {
    const stub = rpcStub({ attribute: attributeLogsFor(990) });
    const method = new MethodEthr({ rpcUrls: { [CHAIN_ID]: RPC_URL }, fetchImpl: stub.fetchImpl });
    for (let i = 0; i < 12; i++) {
      await expect(method.resolve(ethrDid(i))).resolves.toBeDefined();
    }
  });
});
