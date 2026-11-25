/**
 * 取り直した did:webvh の解決が解決スコープ（`ResolutionWorkBudget`）へ課金する量。
 *
 * 拡張の in-flight 予算は、witness を使う解決が追加の取得ぶんを確保できなかったとき、フック `beforeWitnessFile` で 1 回目を
 * 捨てて 2 回分で取り直す。1 回目の課金は残し、2 回目はその分を控除枠に
 * するので、課金の合計は `max(1 回目, 2 回目)`:
 * - 2 回目が正規に成功すれば二重計上されない（予算ぎりぎりの正規の解決が競合のときだけ 2001 にならない）。
 * - 2 回目が安く失敗しても 1 回目の課金が残る（全額差し戻すと、1 回目に最大の署名検証をさせて捨て、2 回目を安く失敗させる
 *   繰り返しで予算が減らないまま実作業だけが積み上がる）。実作業は計上額の高々 2 倍。
 * 実作業は `verifyEd25519`（署名検証）の呼び出し回数で数える。
 */

import { afterEach, beforeEach, describe, expect, it, spyOn } from 'bun:test';
import * as ed25519 from '../../../../keymanager/ed25519.js';
import {
  createResolutionWorkBudget,
  DEFAULT_MAX_SCOPE_BODY_LENGTH,
  DEFAULT_MAX_SCOPE_WORK_UNITS,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_SIGNATURE,
} from '../../../resolution-budget.js';
import { resolveWithinScope } from '../../../resolution-charge.js';
import { createWebVhAttemptLedger, resolveDidWebVhHooked } from '../../resolve.js';
import {
  appendSigned,
  INVALID_DID,
  mockWitnessHost,
  signedGenesis,
  witnessKey,
  witnessProofFor,
} from '../v1/log-builders.js';
import { restoreFetch, toJsonl } from '../webvh-fixtures.js';

const REFUSE = new Error('witness-budget-unavailable');

let verifyCalls = 0;
let verifySpy: ReturnType<typeof spyOn> | undefined;

beforeEach(() => {
  verifyCalls = 0;
  const real = ed25519.verifyEd25519;
  verifySpy = spyOn(ed25519, 'verifyEd25519').mockImplementation((...args) => {
    verifyCalls += 1;
    return real(...args);
  });
});

afterEach(() => {
  verifySpy?.mockRestore();
  restoreFetch();
});

/** 拡張の BudgetedMethodWebVh と同じ流れ: 1 回目はフックで拒む（witness が必要なとき）、2 回目は同じ控えで取り直す。 */
async function resolveWithRetry(did: string, scope: ResolutionWorkBudget) {
  const ledger = createWebVhAttemptLedger();
  try {
    return await resolveDidWebVhHooked(did, scope, {
      ledger,
      beforeWitnessFile: () => {
        throw REFUSE;
      },
    });
  } catch (error) {
    if (error !== REFUSE) {
      throw error;
    }
  }
  return resolveDidWebVhHooked(did, scope, { ledger });
}

/** `versions` 版の、witness を宣言する Log（と did-witness.json の本文）。 */
async function witnessedLog(versions: number, domain = 'vericerts.io') {
  const w1 = witnessKey();
  const { key, did, genesis } = signedGenesis({
    domain,
    witness: { threshold: 1, witnesses: [{ id: w1.id }] },
  });
  const log = [genesis];
  while (log.length < versions) {
    log.push(appendSigned(log, key));
  }
  const last = log[log.length - 1] as (typeof log)[number];
  const file = JSON.stringify([
    { versionId: last.versionId, proof: [await witnessProofFor(last.versionId, w1)] },
  ]);
  return { did, log, file };
}

const chargedOf = (scope: ResolutionWorkBudget) => ({
  units: DEFAULT_MAX_SCOPE_WORK_UNITS - scope.remaining,
  body: DEFAULT_MAX_SCOPE_BODY_LENGTH - scope.remainingBodyLength,
});

/** 1 回の完全な解決（Log・witness とも）が課金する量（スコープなしの控えだけの解決で測る）。 */
async function oneResolutionCost(did: string) {
  const scope = createResolutionWorkBudget();
  await resolveDidWebVhHooked(did, scope, { ledger: createWebVhAttemptLedger() });
  return chargedOf(scope);
}

describe('取り直した解決の課金: max(1 回目, 2 回目)', () => {
  it('予算ぎりぎり（1 回の解決ぶんだけ）のスコープでも、取り直した正規の解決は 2001 にならず、課金は 1 回ぶんちょうど', async () => {
    const { did, log, file } = await witnessedLog(3);
    mockWitnessHost(log, file);
    const cost = await oneResolutionCost(did);
    expect(cost.units).toBeGreaterThan(0);
    expect(cost.body).toBeGreaterThan(0);
    const scope = createResolutionWorkBudget(cost.units, cost.body);

    expect((await resolveWithRetry(did, scope)).id).toBe(did);

    expect(scope.remaining).toBe(0);
    expect(scope.remainingBodyLength).toBe(0);
  });

  it('取り直した解決の課金は、取り直さない 1 回の解決と同じ（resolveWithinScope 越しの保持量の計上も含めて）', async () => {
    const { did, log, file } = await witnessedLog(5);
    mockWitnessHost(log, file);
    const control = createResolutionWorkBudget();
    await resolveWithinScope(control, (view) =>
      resolveDidWebVhHooked(did, view, { ledger: createWebVhAttemptLedger() }),
    );

    const retried = createResolutionWorkBudget();
    await resolveWithinScope(retried, (view) => resolveWithRetry(did, view));

    expect(retried.remaining).toBe(control.remaining);
    expect(retried.remainingBodyLength).toBe(control.remainingBodyLength);
  });

  it('控えは 1 回の取り直しでだけ使われる（取り直し後の控えは空で、次の解決へ控除は持ち越されない）', async () => {
    const { did, log, file } = await witnessedLog(3);
    mockWitnessHost(log, file);
    const ledger = createWebVhAttemptLedger();
    const scope = createResolutionWorkBudget();
    await resolveDidWebVhHooked(did, scope, {
      ledger,
      beforeWitnessFile: () => {
        throw REFUSE;
      },
    }).catch(() => undefined);
    expect(ledger.units).toBeGreaterThan(0);

    await resolveDidWebVhHooked(did, scope, { ledger });
    expect(ledger).toEqual({ units: 0, body: 0 });

    const before = scope.remaining;
    await resolveDidWebVhHooked(did, scope, { ledger });
    expect(before - scope.remaining).toBe((await oneResolutionCost(did)).units);
  });

  it('同じスコープを並行して使う別の解決の消費は変わらない（課金は自分の分だけ）', async () => {
    const { did, log, file } = await witnessedLog(4);
    mockWitnessHost(log, file);
    const cost = await oneResolutionCost(did);
    const scope = createResolutionWorkBudget();

    const results = await Promise.all([
      resolveWithRetry(did, scope),
      resolveDidWebVhHooked(did, scope, { ledger: createWebVhAttemptLedger() }),
      resolveWithRetry(did, scope),
    ]);

    expect(results.map((document) => document.id)).toEqual([did, did, did]);
    // 3 件がそれぞれ 1 回ぶんだけ課金される（取り直した 2 件も二重計上されず、他の解決の消費も消えない）。
    expect(chargedOf(scope)).toEqual({ units: 3 * cost.units, body: 3 * cost.body });
    expect(scope.remaining).toBeGreaterThanOrEqual(0);
  });
});

describe('悪意ある Log: 1 回目に最大の仕事をさせて捨て、2 回目を安く失敗させる繰り返し', () => {
  const VERSIONS = 50;
  const SIGNATURE_LIMIT = DEFAULT_MAX_SCOPE_WORK_UNITS / WORK_UNITS_PER_SIGNATURE;
  /** 上限（署名 1,024 回ぶん）の手前まで完全に解決される DID の数（1 DID が 50 回ぶん → 20 個）。 */
  const FULL_RESOLUTIONS = Math.floor(SIGNATURE_LIMIT / VERSIONS);
  /** 上限に達する DID（21 個目）と、達したあとの DID（22 個目）まで。これ以上作っても検証されず、作る署名が無駄になる。 */
  const DIDS = FULL_RESOLUTIONS + 2;

  /**
   * DID ごとの Log（`DIDS` × `VERSIONS` 版の署名）の生成は、このテストの大半を占める。ケース間で変わらず（ホストの応答は
   * `hostileHosts` がケースごとに作る）、DID は生成した Log の scid から決まるので、1 回だけ作ってケースで使い回す。
   */
  let hostileLogs: Promise<{ hosted: Map<string, string>; dids: string[] }> | undefined;
  function sharedHostileLogs() {
    hostileLogs ??= (async () => {
      const hosted = new Map<string, string>();
      const dids: string[] = [];
      for (let i = 0; i < DIDS; i += 1) {
        const { did, log } = await witnessedLog(VERSIONS, `h${i}.example.com`);
        hosted.set(`h${i}.example.com`, toJsonl(log));
        dids.push(did);
      }
      return { hosted, dids };
    })();
    return hostileLogs;
  }

  /**
   * ホスト群の応答。`log-404`: did.jsonl は 1 回目だけ witness を名乗る Log を返し、2 回目以降は 404（安く失敗）。
   * `witness-404`: did.jsonl は毎回 Log を返し（2 回目も Log の検証をさせる）、did-witness.json だけ 404。
   */
  function hostileHosts(hosted: ReadonlyMap<string, string>, mode: 'log-404' | 'witness-404') {
    const served = new Map<string, number>();
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      );
      const body = hosted.get(url.host);
      const count = (served.get(url.host) ?? 0) + 1;
      served.set(url.host, count);
      const fail =
        body === undefined ||
        (mode === 'log-404' ? count > 1 : url.pathname.endsWith('/did-witness.json'));
      const response = fail
        ? new Response('', { status: 404 })
        : new Response(body, { status: 200, headers: { 'content-type': 'application/jsonl' } });
      Object.defineProperty(response, 'url', { value: url.href, configurable: true });
      return response;
    }) as unknown as typeof fetch;
  }

  /**
   * bun test の既定（5 秒）では、負荷のあるホストで足りない。署名の検証回数は課金の上限（1,024 回、`witness-404` は 2 回目の
   * Log 検証ぶんで約 2 倍）で決まり、DID や版を減らしても減らせない。無負荷での実測は `log-404` が約 1.3 秒、`witness-404` が約 1.5 秒
   * （Log の生成を含む単独実行で約 1.9 秒）。1 コアを 3 プロセスで取り合う負荷では `witness-404` が約 4.6 秒（Log を使い回す前は
   * 6.6〜7.8 秒で既定の 5 秒を超えた）まで伸びる。数倍に伸びても落ちない余裕として 10 倍強の 20 秒にしている。
   */
  const HOSTILE_RESOLUTION_TIMEOUT_MS = 20_000;

  it.each(['log-404', 'witness-404'] as const)(
    '相異なる DID を繰り返しても（2 回目の失敗の形: %s）、実作業（署名検証）は課金額の高々 2 倍で、課金は上限を超えず、上限に達したら以降は 2001 になる',
    async (mode) => {
      const { hosted, dids } = await sharedHostileLogs();
      hostileHosts(hosted, mode);
      const scope = createResolutionWorkBudget();
      const outcomes: string[] = [];

      for (const did of dids) {
        await resolveWithRetry(did, scope).then(
          () => outcomes.push('ok'),
          (error: unknown) =>
            outcomes.push(error instanceof Error && 'code' in error ? String(error.code) : 'other'),
        );
      }

      const gross = verifyCalls * WORK_UNITS_PER_SIGNATURE;
      const charged = DEFAULT_MAX_SCOPE_WORK_UNITS - scope.remaining;
      // 実作業は課金額の高々 2 倍（1 回目 + 2 回目 <= 2 * max(1 回目, 2 回目)）。全額差し戻しでは課金が 0 のまま実作業が積み上がった。
      expect(gross).toBeLessThanOrEqual(2 * charged);
      // 課金は上限を超えず（0 に張り付く）、実作業は上限の 2 倍以内。
      expect(scope.remaining).toBeGreaterThanOrEqual(0);
      expect(charged).toBeLessThanOrEqual(DEFAULT_MAX_SCOPE_WORK_UNITS);
      expect(gross).toBeLessThanOrEqual(2 * DEFAULT_MAX_SCOPE_WORK_UNITS);
      // 1 回目の課金は残り、上限（署名 1,024 回ぶん）の手前まで積み上がる。
      expect(charged).toBeGreaterThanOrEqual(
        FULL_RESOLUTIONS * VERSIONS * WORK_UNITS_PER_SIGNATURE,
      );
      // 上限に達したあとは、取得も署名検証も始めずに 2001（resolution_work_limit）で拒否される。
      expect(outcomes.at(-1)).toBe(String(INVALID_DID.code));
      console.info(
        JSON.stringify({
          amplification: {
            mode,
            gross,
            charged,
            limit: DEFAULT_MAX_SCOPE_WORK_UNITS,
            grossOverLimit: gross / DEFAULT_MAX_SCOPE_WORK_UNITS,
            grossOverCharged: gross / charged,
          },
        }),
      );
    },
    HOSTILE_RESOLUTION_TIMEOUT_MS,
  );
});

describe('控えは max(1 回目, 2 回目) を保つ（2 回目の消費が 1 回目より小さくても減らさない）', () => {
  const throwing = {
    beforeWitnessFile: () => {
      throw REFUSE;
    },
  };

  it('2 回目にもフックを付けて 2 回目が投げる経路（2 回目の消費 < 1 回目）でも、控えは 1 回目の課金額のまま、課金も 1 回目ぶんだけ', async () => {
    const big = await witnessedLog(8, 'big.example.com');
    const small = await witnessedLog(1, 'small.example.com');
    const hosted = new Map([
      ['big.example.com', toJsonl(big.log)],
      ['small.example.com', toJsonl(small.log)],
    ]);
    const servedLog = () => {
      globalThis.fetch = (async (input: string | URL | Request) => {
        const url = new URL(
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
        );
        const response = new Response(hosted.get(url.host) ?? '', {
          status: 200,
          headers: { 'content-type': 'application/jsonl' },
        });
        Object.defineProperty(response, 'url', { value: url.href, configurable: true });
        return response;
      }) as unknown as typeof fetch;
    };
    servedLog();
    const scope = createResolutionWorkBudget();
    const ledger = createWebVhAttemptLedger();

    await expect(resolveDidWebVhHooked(big.did, scope, { ledger, ...throwing })).rejects.toBe(
      REFUSE,
    );
    const c1 = { ...ledger };
    const chargedAfterFirst = chargedOf(scope);
    expect(c1.units).toBeGreaterThan(0);
    expect(chargedAfterFirst).toEqual(c1);

    // 2 回目（同じ控え）は小さい Log を解決して、またフックで投げる: 消費 < c1 だが控えは c1 以上のまま。
    await expect(resolveDidWebVhHooked(small.did, scope, { ledger, ...throwing })).rejects.toBe(
      REFUSE,
    );
    expect(ledger.units).toBeGreaterThanOrEqual(c1.units);
    expect(ledger.body).toBeGreaterThanOrEqual(c1.body);
    expect(ledger).toEqual(c1);
    // 課金は max(c1, c2) = c1 のまま（2 回目は控除枠に収まる）。
    expect(chargedOf(scope)).toEqual(c1);
  });
});
