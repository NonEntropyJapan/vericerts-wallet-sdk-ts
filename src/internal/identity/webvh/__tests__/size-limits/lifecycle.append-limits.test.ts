/**
 * `createDidWebVh` / `updateDidWebVh` が検証側の上限（版数・1 行・ログ全体・鍵ハッシュ）を超えるログを作らない。
 *
 * DID Log は追記専用のハッシュ鎖で、上限を超えて追記した DID は以後永久に解決不能になる。生成側が検証側と同じ定数で
 * 署名前に拒否することを、**自分で作ったログを自分で検証できる**ラウンドトリップ（`parseDidLog` + `verifyChain`）で pin する。
 * 実時間ではなく、受理された版数・行長・バイト数・例外の種別で確認し、版数・鍵数・サイズの比率を変えた複数形状で見る。
 */

import { afterEach, describe, expect, it, setDefaultTimeout } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../../__tests__/heavy-input-timeout.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { MAX_DOCUMENT_BYTES } from '../../../../http/body-limit.js';
import {
  deriveVersionId,
  nextVersionTime,
  parseDidLog,
  updateKeyHash,
  type WebVhLogEntry,
} from '../../codec.js';
import {
  MAX_KEY_HASHES_PER_LOG,
  MAX_KEYS_PER_ENTRY,
  MAX_LOG_ENTRIES,
  MAX_LOG_ENTRY_CHARS,
} from '../../limits.js';
import { createDidWebVh, resolveDidWebVh, updateDidWebVh } from '../../method-webvh.js';
import { verifyChain } from '../../verify.js';
import {
  generateKey,
  mockFetchOnce,
  restoreFetch,
  signEntry,
  type TestKey,
  toJsonl,
} from '../webvh-fixtures.js';

setDefaultTimeout(HEAVY_INPUT_TIMEOUT_MS);

afterEach(() => {
  restoreFetch();
});

function expectOversized(fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(ErrorCodes.INVALID_DID);
    expect((err as VericertsError).context).toMatchObject({ reason: 'did_log_too_large' });
    return;
  }
  throw new Error('should have thrown');
}

type Doc = Parameters<typeof createDidWebVh>[0]['document'];
const withServices = (service: unknown[]): Doc => ({ service }) as unknown as Doc;

/** 自分で作ったログを `parseDidLog` + `verifyChain` で検証する（解決側と同じ入口）。 */
function expectSelfVerifies(did: string, log: readonly WebVhLogEntry[]): void {
  const text = toJsonl(log);
  expect(new TextEncoder().encode(text).length).toBeLessThanOrEqual(MAX_DOCUMENT_BYTES);
  const entries = parseDidLog(text);
  verifyChain(entries, did, (log[0] as WebVhLogEntry).parameters.scid as string);
}

/** 次版を `updateDidWebVh` で作って署名する。 */
function append(
  log: readonly WebVhLogEntry[],
  key: TestKey,
  extra: Partial<Parameters<typeof updateDidWebVh>[0]> = {},
  state = (log[0] as WebVhLogEntry).state,
): WebVhLogEntry {
  return signEntry(updateDidWebVh({ previousLog: log, state, ...extra }), key);
}

describe('版数（MAX_LOG_ENTRIES）', () => {
  it('512 版まで追記でき、自分で検証できる。513 版目は署名前に 2001 で拒否される', () => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({ domain: 'example.com', updateKeys: [key.multikey] });
    const log: WebVhLogEntry[] = [signEntry(logEntry, key)];
    while (log.length < MAX_LOG_ENTRIES) {
      log.push(append(log, key));
    }
    expect(log).toHaveLength(MAX_LOG_ENTRIES);
    expectSelfVerifies(did, log);
    expectOversized(() => updateDidWebVh({ previousLog: log, state: logEntry.state }));
  });
});

describe('1 行の長さ（MAX_LOG_ENTRY_CHARS）', () => {
  const key = generateKey();
  const shapes: ReadonlyArray<readonly [string, (n: number) => Doc]> = [
    [
      '少数の巨大要素（1 つの長い文字列）',
      (n) => withServices([{ id: '#a', type: 'T', serviceEndpoint: 'a'.repeat(n) }]),
    ],
    [
      '多数の極小要素（極小 service を n 個）',
      (n) =>
        withServices(
          Array.from({ length: n }, (_, i) => ({ id: `#${i}`, type: 'T', serviceEndpoint: 'e' })),
        ),
    ],
    [
      '中間（256 文字の service を n 個）',
      (n) =>
        withServices(
          Array.from({ length: n }, (_, i) => ({
            id: `#${i}`,
            type: 'T',
            serviceEndpoint: 'm'.repeat(256),
          })),
        ),
    ],
  ];
  const upperBounds = [MAX_LOG_ENTRY_CHARS, MAX_LOG_ENTRY_CHARS / 8, MAX_LOG_ENTRY_CHARS / 256];

  it.each(
    shapes.map((shape, i) => [shape[0], shape[1], upperBounds[i] as number] as const),
  )('%s: 生成が受理する最大サイズの genesis は署名しても検証でき、超えると 2001 で拒否される', (_name, doc, upper) => {
    const accepts = (n: number): boolean => {
      try {
        createDidWebVh({ domain: 'example.com', updateKeys: [key.multikey], document: doc(n) });
        return true;
      } catch (err) {
        expect((err as VericertsError).context).toMatchObject({ reason: 'did_log_too_large' });
        return false;
      }
    };
    // 受理する最大の n を二分探索する（0 は必ず受理、`upper` は必ず拒否）。
    let lo = 0;
    let hi = Math.ceil(upper);
    expect(accepts(hi)).toBe(false);
    while (hi - lo > 1) {
      const mid = Math.floor((lo + hi) / 2);
      if (accepts(mid)) {
        lo = mid;
      } else {
        hi = mid;
      }
    }
    expect(lo).toBeGreaterThan(0);
    const { did, logEntry } = createDidWebVh({
      domain: 'example.com',
      updateKeys: [key.multikey],
      document: doc(lo),
    });
    const signed = signEntry(logEntry, key);
    // 署名後の 1 行（proof 込み）が検証側の上限に収まり、そのまま検証できる。
    expect(JSON.stringify(signed).length).toBeLessThanOrEqual(MAX_LOG_ENTRY_CHARS);
    expectSelfVerifies(did, [signed]);
    expect(accepts(hi)).toBe(false);
  });

  it('updateDidWebVh も同じ上限で拒否する（受理した次版は署名しても検証できる）', () => {
    const { did, logEntry } = createDidWebVh({ domain: 'example.com', updateKeys: [key.multikey] });
    const genesis = signEntry(logEntry, key);
    const big = (n: number) => ({
      ...logEntry.state,
      service: [{ id: '#a', type: 'T', serviceEndpoint: 'a'.repeat(n) }],
    });
    expectOversized(() =>
      updateDidWebVh({ previousLog: [genesis], state: big(MAX_LOG_ENTRY_CHARS) }),
    );
    // 上限一杯に近い（proof の余白だけ残す）サイズは受理され、署名後も検証できる。
    const fits = signEntry(
      updateDidWebVh({ previousLog: [genesis], state: big(MAX_LOG_ENTRY_CHARS - 2_000) }),
      key,
    );
    expectSelfVerifies(did, [genesis, fits]);
  });
});

describe('ログ全体（MAX_DOCUMENT_BYTES）', () => {
  // [名前, 文字, 1 版あたりの文字数]。マルチバイトは「文字数では収まるがバイト数で超える」形状。
  it.each([
    ['ASCII の大きな版を並べる', 'a', 100_000],
    ['ASCII の中くらいの版を並べる', 'a', 30_000],
    ['3 バイト文字（文字数はバイト数の 1/3）', '€', 40_000],
  ] as const)('%s: 受理されたログは fetch 上限に収まり、そのまま解決できる', async (_n, ch, size) => {
    const key = generateKey();
    const { did, logEntry } = createDidWebVh({ domain: 'example.com', updateKeys: [key.multikey] });
    const log: WebVhLogEntry[] = [signEntry(logEntry, key)];
    const state = {
      ...logEntry.state,
      service: [{ id: '#a', type: 'T', serviceEndpoint: ch.repeat(size) }],
    };
    let rejected = false;
    for (let i = 0; i < MAX_LOG_ENTRIES && !rejected; i++) {
      try {
        log.push(append(log, key, {}, state));
      } catch (err) {
        expect((err as VericertsError).context).toMatchObject({ reason: 'did_log_too_large' });
        rejected = true;
      }
    }
    // 総量で拒否された（版数の上限には届かない）。
    expect(rejected).toBe(true);
    expect(log.length).toBeLessThan(MAX_LOG_ENTRIES);
    const bytes = new TextEncoder().encode(toJsonl(log)).length;
    expect(bytes).toBeLessThanOrEqual(MAX_DOCUMENT_BYTES);
    // 次の版を足すと上限を超える（余白は proof 1 件ぶんにとどまる）。
    expect(bytes + size * (ch === 'a' ? 1 : 3)).toBeGreaterThan(MAX_DOCUMENT_BYTES - 2_048);
    mockFetchOnce(toJsonl(log));
    const resolved = await resolveDidWebVh(did);
    expect(resolved.id).toBe(did);
  });
});

describe('事前コミット鍵ハッシュ（MAX_KEY_HASHES_PER_LOG）', () => {
  // [1 版あたりの鍵数, 受理される最大版数]。2 版目以降 1 版あたり鍵数ぶんのハッシュが計算される:
  // 4096 / 32 = 128 版ぶん → 初版を足して 129 版、4096 / 16 = 256 → 257 版。
  it.each([
    [MAX_KEYS_PER_ENTRY, MAX_KEY_HASHES_PER_LOG / MAX_KEYS_PER_ENTRY + 1],
    [16, MAX_KEY_HASHES_PER_LOG / 16 + 1],
    [4, MAX_LOG_ENTRIES], // 鍵数が少なければ版数の上限が先に効く（4 × 511 < 4096）
  ])('%d 鍵 / 版: %d 版まで追記でき、自分で検証できる。次の版は署名前に 2001 で拒否される', (keys, expectedEntries) => {
    const signer = generateKey();
    const keySet = [signer, ...Array.from({ length: keys - 1 }, () => generateKey())];
    const updateKeys = keySet.map((k) => k.multikey);
    const nextKeyHashes = updateKeys.map(updateKeyHash);
    const { did, logEntry } = createDidWebVh({
      domain: 'example.com',
      updateKeys,
      nextKeyHashes,
    });
    const log: WebVhLogEntry[] = [signEntry(logEntry, signer)];
    let rejected: unknown;
    while (rejected === undefined && log.length <= MAX_LOG_ENTRIES) {
      try {
        log.push(append(log, signer, { updateKeys, nextKeyHashes }));
      } catch (err) {
        rejected = err;
      }
    }
    expect(log).toHaveLength(expectedEntries);
    expect(rejected).toBeInstanceOf(VericertsError);
    expect((rejected as VericertsError).context).toMatchObject({ reason: 'did_log_too_large' });
    expectSelfVerifies(did, log);
    // 生成側が拒否した版は、検証側も同じ理由で拒否する（上限が 2 か所で食い違わない）。
    if (expectedEntries < MAX_LOG_ENTRIES) {
      const previous = log[log.length - 1] as WebVhLogEntry;
      const draft: WebVhLogEntry = {
        versionId: '',
        versionTime: nextVersionTime(previous.versionTime),
        parameters: { updateKeys, nextKeyHashes },
        state: logEntry.state,
      };
      const forged = signEntry(
        { ...draft, versionId: deriveVersionId(draft, log.length + 1, previous.versionId) },
        signer,
      );
      expectOversized(() => verifyChain([...log, forged], did, log[0]?.parameters.scid as string));
    }
  });
});
