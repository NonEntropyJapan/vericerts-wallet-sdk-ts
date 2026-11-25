/**
 * 解決スコープ（VP 1 件 / `verifyDIDConfiguration` 1 回）全体の検証仕事量の予算。
 *
 * `createBoundedResolver` は相異なる DID 数（32）と DID 長しか縛らないため、1 本ごとに最大 512 版（署名検証
 * 512 回）の did:webvh を 32 個並べると、署名検証前の解決だけで Node が 26 秒止まった。署名検証の総回数を
 * スコープ共通の予算で数え、超過は `2001`（`resolution_work_limit`）で拒否する。実時間ではなく
 * Ed25519 検証の呼び出し回数と例外の種別で pin し、版数と DID 数の比率を変えた複数形状で確認する。
 */

import { afterEach, describe, expect, it, spyOn } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import * as ed25519Module from '../../../../keymanager/ed25519.js';
import { createBoundedResolver, type DidResolverLike } from '../../../bounded-resolver.js';
import {
  DEFAULT_MAX_SCOPE_BODY_LENGTH,
  DEFAULT_MAX_SCOPE_WORK_UNITS,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_SIGNATURE,
} from '../../../resolution-budget.js';
import { Resolver } from '../../../resolver.js';
import { deriveVersionId, nextVersionTime, type WebVhLogEntry } from '../../codec.js';
import { createDidWebVh, MethodWebVh } from '../../method-webvh.js';
import { generateKey, restoreFetch, signEntry, toJsonl } from '../webvh-fixtures.js';

afterEach(() => {
  restoreFetch();
});

/** テストでは予算を小さく上書きして、署名の生成・検証コストを抑える（既定値は別テストで pin する）。 */
const MAX_SIGNATURES = 64;

interface SignedLog {
  readonly did: string;
  readonly text: string;
}

/** `entryCount` 版の正規な did:webvh ログ（`domain` ごとに別 DID）。 */
function buildLog(domain: string, entryCount: number): SignedLog {
  const key = generateKey();
  const { did, logEntry } = createDidWebVh({ domain, updateKeys: [key.multikey] });
  const log: WebVhLogEntry[] = [signEntry(logEntry, key)];
  while (log.length < entryCount) {
    const previous = log[log.length - 1] as WebVhLogEntry;
    const draft: WebVhLogEntry = {
      versionId: '',
      versionTime: nextVersionTime(previous.versionTime),
      parameters: {},
      state: logEntry.state,
    };
    const versionId = deriveVersionId(draft, log.length + 1, previous.versionId);
    log.push(signEntry({ ...draft, versionId }, key));
  }
  return { did, text: toJsonl(log) };
}

/** ホスト名ごとに別の DID Log を返すグローバル `fetch` のモックを入れ、取得回数の記録を返す。 */
function serveLogs(logs: readonly SignedLog[]): { fetches: string[] } {
  const fetches: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    fetches.push(url);
    const log = logs.find((candidate) => url.includes(candidate.did.split(':')[3] as string));
    const response = new Response(log?.text ?? '', {
      status: log === undefined ? 404 : 200,
      headers: { 'content-type': 'application/jsonl' },
    });
    Object.defineProperty(response, 'url', { value: url, configurable: true });
    return response;
  }) as unknown as typeof fetch;
  return { fetches };
}

function scopedResolver(): DidResolverLike {
  const resolver = new Resolver();
  resolver.register(new MethodWebVh());
  return createBoundedResolver(resolver, {
    maxWorkUnits: MAX_SIGNATURES * WORK_UNITS_PER_SIGNATURE,
  });
}

async function resolveAll(
  bounded: DidResolverLike,
  logs: readonly SignedLog[],
): Promise<PromiseSettledResult<unknown>[]> {
  const results: PromiseSettledResult<unknown>[] = [];
  for (const log of logs) {
    results.push(...(await Promise.allSettled([bounded.resolve(log.did)])));
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

describe('createBoundedResolver: スコープ全体の検証仕事量', () => {
  // [DID 数, 1 本あたりの版数]。どれも 1 本ごとの上限（512 版）には収まるが、総署名数は予算を超える。
  it.each([
    [3, 30],
    [8, 12],
    [20, 5],
  ])('%d 個の DID × %d 版は、署名検証がちょうど予算ぶんで止まる', async (didCount, entryCount) => {
    expect(didCount * entryCount).toBeGreaterThan(MAX_SIGNATURES);
    const logs = Array.from({ length: didCount }, (_, i) =>
      buildLog(`d${i}.example.com`, entryCount),
    );
    serveLogs(logs);
    const spy = spyOn(ed25519Module, 'verifyEd25519');
    try {
      const results = await resolveAll(scopedResolver(), logs);
      expect(spy).toHaveBeenCalledTimes(MAX_SIGNATURES);
      // 予算に収まる先頭の DID は解決でき、尽きた DID は 2001 で拒否される。
      const fulfilled = Math.floor(MAX_SIGNATURES / entryCount);
      expect(results.slice(0, fulfilled).every((r) => r.status === 'fulfilled')).toBe(true);
      expectWorkLimit(results[fulfilled]);
    } finally {
      spy.mockRestore();
    }
  });

  it('予算が尽きたスコープでは、後続の DID の DID Log を取得しない', async () => {
    // 30 版 × 2 本 = 60 署名は予算内。3 本目は残り 4 署名で尽き、スコープの残りは 0 になる。
    const logs = Array.from({ length: 3 }, (_, i) => buildLog(`e${i}.example.com`, 30));
    const extra = buildLog('e9.example.com', 2);
    const { fetches } = serveLogs([...logs, extra]);
    const bounded = scopedResolver();
    expectWorkLimit((await resolveAll(bounded, logs))[2]);
    const fetchedBefore = fetches.length;
    expectWorkLimit((await resolveAll(bounded, [extra]))[0]);
    expect(fetches).toHaveLength(fetchedBefore);
  });

  it('予算内の解決は従来どおり通る（40 版の 1 本 + 小さな DID 数本）', async () => {
    const logs = [
      buildLog('big.example.com', 40),
      ...Array.from({ length: 8 }, (_, i) => buildLog(`s${i}.example.com`, 3)),
    ];
    serveLogs(logs);
    const results = await resolveAll(scopedResolver(), logs);
    expect(results.every((r) => r.status === 'fulfilled')).toBe(true);
  });

  it('スコープ外の単独解決（Resolver を直接使う）は予算に影響されない', async () => {
    const logs = Array.from({ length: 3 }, (_, i) => buildLog(`o${i}.example.com`, 30));
    serveLogs(logs);
    const resolver = new Resolver();
    resolver.register(new MethodWebVh());
    for (const log of logs) {
      await expect(resolver.resolve(log.did)).resolves.toBeDefined();
    }
  });

  it('既定のスコープ予算は署名検証 1,024 回ぶんで、下位 resolver へ共通の予算が渡る', async () => {
    const scopes: Array<ResolutionWorkBudget | undefined> = [];
    const bounded = createBoundedResolver({
      resolve: async (_did, scope) => {
        scopes.push(scope);
        throw new VericertsError(ErrorCodes.DID_NOT_FOUND);
      },
    });
    await Promise.allSettled([bounded.resolve('did:x:a'), bounded.resolve('did:x:b')]);
    expect(scopes).toHaveLength(2);
    // 解決ごとに計上を追跡するビューが渡るが、予算の状態は全解決で 1 つを共有する。
    expect(scopes[0]).toBeDefined();
    if (scopes[0] !== undefined) {
      scopes[0].remaining -= 7;
    }
    expect(scopes[1]?.remaining).toBe(DEFAULT_MAX_SCOPE_WORK_UNITS - 7);
    if (scopes[0] !== undefined) {
      scopes[0].remaining += 7;
    }
    expect(scopes[0]?.remaining).toBe(DEFAULT_MAX_SCOPE_WORK_UNITS);
    expect(scopes[0]?.remainingBodyLength).toBe(DEFAULT_MAX_SCOPE_BODY_LENGTH);
    expect(DEFAULT_MAX_SCOPE_WORK_UNITS).toBe(1024 * WORK_UNITS_PER_SIGNATURE);
  });
});
