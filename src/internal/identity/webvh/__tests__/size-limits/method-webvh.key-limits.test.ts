/**
 * did:webvh の updateKeys / nextKeyHashes の件数・総ハッシュ回数の上限。
 *
 * 事前コミット検証は宣言された鍵ごとに SHA-256 + base58 を計算する。1 エントリの件数にも総数にも上限が無いと、
 * 1 MiB 未満のログ 1 通（512 版 × 230 鍵）で `verifyChain` が Node で約 2 秒同期 CPU を占有した。
 * 実時間ではなく、ハッシュ関数の呼び出し回数・例外の種別で pin する。件数と版数の比率を変えた複数形状で確認する。
 */

import { afterEach, describe, expect, it, setDefaultTimeout, spyOn } from 'bun:test';
import { HEAVY_INPUT_TIMEOUT_MS } from '../../../../__tests__/heavy-input-timeout.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import * as codecModule from '../../codec.js';
import {
  deriveVersionId,
  nextVersionTime,
  parseDidLog,
  updateKeyHash,
  updateKeysOf,
  type WebVhLogEntry,
} from '../../codec.js';
import { MAX_KEY_HASHES_PER_LOG, MAX_KEYS_PER_ENTRY, MAX_LOG_ENTRIES } from '../../limits.js';
import { createDidWebVh } from '../../method-webvh.js';
import { verifyChain } from '../../verify.js';
import { generateKey, restoreFetch, signEntry, toJsonl } from '../webvh-fixtures.js';

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

/**
 * 全版が「同じ `keysPerEntry` 件の updateKeys」を宣言するログを作る。初版が全鍵ぶんの nextKeyHashes を
 * 事前コミットするので、2 版目以降は宣言された鍵ごとに事前コミット検証のハッシュ計算が走る。
 * 署名できるのは先頭の実鍵だけ（残りは形式だけの鍵で、検証は proof の `verificationMethod` を見る）。
 */
function buildKeyLog(entryCount: number, keysPerEntry: number) {
  const signer = generateKey();
  const decoys = Array.from({ length: keysPerEntry - 1 }, (_, i) => `zDecoy${i}`);
  const allKeys = [signer.multikey, ...decoys];
  const { did, logEntry } = createDidWebVh({
    domain: 'vericerts.io',
    updateKeys: allKeys.slice(0, 1),
    nextKeyHashes: allKeys.map((key) => updateKeyHash(key)),
  });
  const log: WebVhLogEntry[] = [signEntry(logEntry, signer)];
  while (log.length < entryCount) {
    const previous = log[log.length - 1] as WebVhLogEntry;
    const draft: WebVhLogEntry = {
      versionId: '',
      versionTime: nextVersionTime(previous.versionTime),
      // 事前コミット中は updateKeys と nextKeyHashes を毎版明示する（v1.0）。
      parameters: { updateKeys: allKeys, nextKeyHashes: allKeys.map((key) => updateKeyHash(key)) },
      state: logEntry.state,
    };
    const versionId = deriveVersionId(draft, log.length + 1, previous.versionId);
    log.push(signEntry({ ...draft, versionId }, signer));
  }
  return { did, scid: did.split(':')[2] as string, log };
}

describe('1 エントリの updateKeys / nextKeyHashes の件数上限', () => {
  it('上限ちょうどの鍵数は従来どおり通る', () => {
    const { did, scid, log } = buildKeyLog(2, MAX_KEYS_PER_ENTRY);
    expect(() => verifyChain(parseDidLog(toJsonl(log)), did, scid)).not.toThrow();
  });

  it.each([
    ['updateKeys', MAX_KEYS_PER_ENTRY + 1],
    ['updateKeys（巨大）', 100_000],
  ])('%s が上限を超える行は、ハッシュ計算も署名検証もせず parseDidLog が拒否する', (_label, count) => {
    const { log } = buildKeyLog(1, 1);
    const entry = log[0] as WebVhLogEntry;
    const spy = spyOn(codecModule, 'updateKeyHash');
    try {
      const keys = Array.from({ length: count }, (_, i) => `zK${i}`);
      expectOversized(() =>
        parseDidLog(toJsonl([{ ...entry, parameters: { ...entry.parameters, updateKeys: keys } }])),
      );
      expect(spy).toHaveBeenCalledTimes(0);
    } finally {
      spy.mockRestore();
    }
  });

  it('nextKeyHashes が上限を超える行も parseDidLog が拒否する', () => {
    const { log } = buildKeyLog(1, 1);
    const entry = log[0] as WebVhLogEntry;
    const hashes = Array.from({ length: MAX_KEYS_PER_ENTRY + 1 }, (_, i) => `zH${i}`);
    expectOversized(() =>
      parseDidLog(
        toJsonl([{ ...entry, parameters: { ...entry.parameters, nextKeyHashes: hashes } }]),
      ),
    );
  });

  it('parseDidLog を通らない配列でも updateKeysOf / verifyChain が件数で拒否する', () => {
    const { did, scid, log } = buildKeyLog(1, 1);
    const entry = log[0] as WebVhLogEntry;
    const keys = Array.from({ length: MAX_KEYS_PER_ENTRY + 1 }, (_, i) => `zK${i}`);
    const forged = { ...entry, parameters: { ...entry.parameters, updateKeys: keys } };
    expectOversized(() => updateKeysOf(forged));
    expectOversized(() => verifyChain([forged], did, scid));
  });

  it('生成側（createDidWebVh）も上限超過の updateKeys / nextKeyHashes を拒否する', () => {
    const keys = Array.from({ length: MAX_KEYS_PER_ENTRY + 1 }, () => generateKey().multikey);
    expectOversized(() => createDidWebVh({ domain: 'vericerts.io', updateKeys: keys }));
    expectOversized(() =>
      createDidWebVh({
        domain: 'vericerts.io',
        updateKeys: keys.slice(0, 1),
        nextKeyHashes: keys.map((key) => updateKeyHash(key)),
      }),
    );
  });
});

describe('ログ全体の事前コミット用ハッシュ総数の予算', () => {
  // [版数, 1 版あたりの鍵数]: 少数版 × 上限一杯の鍵 / 中程度 / 多数版 × 少数鍵。どれも 1 版あたりの件数上限は満たす。
  it.each([
    [140, MAX_KEYS_PER_ENTRY],
    [300, 16],
    [MAX_LOG_ENTRIES, 9],
  ])('%d 版 × %d 鍵のログは、ハッシュ計算が予算ちょうどで尽きて拒否される', (entryCount, keys) => {
    const { did, scid, log } = buildKeyLog(entryCount, keys);
    // 予算を超える総数（この形状が「1 版あたりの件数上限」だけでは弾かれないことの確認を兼ねる）。
    expect((entryCount - 1) * keys).toBeGreaterThan(MAX_KEY_HASHES_PER_LOG);
    const spy = spyOn(codecModule, 'updateKeyHash');
    try {
      expectOversized(() => verifyChain(parseDidLog(toJsonl(log)), did, scid));
      expect(spy).toHaveBeenCalledTimes(MAX_KEY_HASHES_PER_LOG);
    } finally {
      spy.mockRestore();
    }
  });

  it.each([
    [128, MAX_KEYS_PER_ENTRY],
    [MAX_LOG_ENTRIES, 8],
  ])('予算内の %d 版 × %d 鍵のログは従来どおり通る', (entryCount, keys) => {
    const { did, scid, log } = buildKeyLog(entryCount, keys);
    expect((entryCount - 1) * keys).toBeLessThanOrEqual(MAX_KEY_HASHES_PER_LOG);
    expect(() => verifyChain(parseDidLog(toJsonl(log)), did, scid)).not.toThrow();
  });
});
