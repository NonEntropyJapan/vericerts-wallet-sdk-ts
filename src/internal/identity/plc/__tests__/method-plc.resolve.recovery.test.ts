/**
 * `MethodPlc.resolve` の `nullified` と 72 時間の回復窓・失効。
 *
 * 取得は `fetchFn` 注入のモックで、実ネットワークには接続しない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { MethodPlc } from '../method-plc.js';
import {
  DIRECTORY,
  dataOf,
  directoryFor,
  documentOf,
  entry,
  expectVericertsError,
  genesis,
  makeKey,
  nextOperation,
  tombstone,
} from './plc.fixtures.js';

const T1 = '2026-10-01T01:00:00.000Z';
const T2 = '2026-10-01T02:00:00.000Z';

describe('MethodPlc.resolve — nullified と 72 時間の回復窓', () => {
  /** 下位鍵（攻撃者に渡った鍵）が T1 に更新し、上位鍵が `recoveryAt` に genesis へ巻き戻す。 */
  async function forkScenario(options: {
    recoveryAt: string;
    recoverWith: 'high' | 'low';
    nullified?: boolean;
  }) {
    const high = makeKey();
    const low = makeKey('P-256');
    const g = await genesis(high, dataOf([high, low]));
    const hijack = await nextOperation(
      g.did,
      g.entries[0] as never,
      { ...g.data, alsoKnownAs: ['at://attacker.example'] },
      low,
    );
    const hijackEntry = entry(g.did, hijack, T1);
    const recoveredData = { ...g.data, alsoKnownAs: ['at://alice.example.com', 'at://recovered'] };
    const recovery = await nextOperation(
      g.did,
      g.entries[0] as never,
      recoveredData,
      options.recoverWith === 'high' ? high : low,
    );
    const entries = [
      g.entries[0] as never,
      { ...hijackEntry, nullified: options.nullified ?? true },
      entry(g.did, recovery, options.recoveryAt),
    ];
    return { g, entries, recoveredData };
  }

  it('上位鍵が 72 時間以内に下位鍵の操作を巻き戻した分岐を採用し、無効化された操作は使わない', async () => {
    const { g, entries, recoveredData } = await forkScenario({
      recoveryAt: '2026-10-04T01:00:00.000Z',
      recoverWith: 'high',
    });
    const dir = directoryFor(g.did, entries, documentOf(g.did, recoveredData));
    const doc = await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did);
    expect(doc.alsoKnownAs).toEqual(['at://alice.example.com', 'at://recovered']);
  });

  it('回復窓（72 時間）を過ぎた巻き戻しは 2010（plc_recovery_invalid）', async () => {
    const { g, entries, recoveredData } = await forkScenario({
      recoveryAt: '2026-10-04T01:00:00.001Z',
      recoverWith: 'high',
    });
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, entries, documentOf(g.did, recoveredData)).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_recovery_invalid',
    );
  });

  it('下位鍵では上位鍵が署名した操作を巻き戻せない（優先度が同じ・低い分岐は 2010）', async () => {
    const high = makeKey();
    const low = makeKey('P-256');
    const g = await genesis(high, dataOf([high, low]));
    const byHigh = await nextOperation(
      g.did,
      g.entries[0] as never,
      { ...g.data, alsoKnownAs: ['at://a'] },
      high,
    );
    const byLow = await nextOperation(
      g.did,
      g.entries[0] as never,
      { ...g.data, alsoKnownAs: ['at://b'] },
      low,
    );
    const entries = [
      g.entries[0] as never,
      { ...entry(g.did, byHigh, T1), nullified: true },
      entry(g.did, byLow, T2),
    ];
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, entries, documentOf(g.did, g.data)).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_recovery_invalid',
    );
  });

  it('同じ鍵が自分の操作を巻き戻そうとする分岐は 2010', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const a = await nextOperation(
      g.did,
      g.entries[0] as never,
      { ...g.data, alsoKnownAs: ['at://a'] },
      key,
    );
    const b = await nextOperation(
      g.did,
      g.entries[0] as never,
      { ...g.data, alsoKnownAs: ['at://b'] },
      key,
    );
    const entries = [
      g.entries[0] as never,
      { ...entry(g.did, a, T1), nullified: true },
      entry(g.did, b, T2),
    ];
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, entries, documentOf(g.did, g.data)).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_recovery_invalid',
    );
  });

  it('ディレクトリが付けた nullified が再生結果と食い違えば 2010（plc_nullified_mismatch）', async () => {
    const { g, entries, recoveredData } = await forkScenario({
      recoveryAt: '2026-10-02T00:00:00.000Z',
      recoverWith: 'high',
      nullified: false,
    });
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, entries, documentOf(g.did, recoveredData)).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_nullified_mismatch',
    );
  });

  it('無効化された分岐の文書が返されても（順序の入れ替え）一致確認で拒否する', async () => {
    const { g, entries } = await forkScenario({
      recoveryAt: '2026-10-02T00:00:00.000Z',
      recoverWith: 'high',
    });
    const hijacked = { ...g.data, alsoKnownAs: ['at://attacker.example'] };
    await expectVericertsError(
      () =>
        new MethodPlc({
          fetchFn: directoryFor(g.did, entries, documentOf(g.did, hijacked)).fetchFn,
        }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_document_mismatch',
    );
  });
});

describe('MethodPlc.resolve — 失効', () => {
  it('最終操作が plc_tombstone なら 2001（plc_deactivated）', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const stone = await tombstone(g.did, g.entries[0] as never, key);
    const entries = [...g.entries, entry(g.did, stone, T1)];
    const dir = directoryFor(g.did, entries, documentOf(g.did, g.data));
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did),
      ErrorCodes.INVALID_DID,
      'plc_deactivated',
    );
    // 失効を確定させたあとは文書を取りに行かない。
    expect(dir.requests.some((r) => r.url === `${DIRECTORY}/${g.did}`)).toBe(false);
  });

  it('tombstone の後ろへ追記した操作は 2010（plc_prev_invalid）', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const stone = entry(g.did, await tombstone(g.did, g.entries[0] as never, key), T1);
    const after = entry(g.did, await nextOperation(g.did, stone, g.data, key), T2);
    const dir = directoryFor(g.did, [...g.entries, stone, after], documentOf(g.did, g.data));
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did),
      ErrorCodes.DID_DOC_INVALID,
      'plc_prev_invalid',
    );
  });

  it('回復窓内に tombstone を上位鍵が巻き戻した場合は復活する', async () => {
    const high = makeKey();
    const low = makeKey('P-256');
    const g = await genesis(high, dataOf([high, low]));
    const stone = await tombstone(g.did, g.entries[0] as never, low);
    const restored = await nextOperation(g.did, g.entries[0] as never, g.data, high);
    const entries = [
      g.entries[0] as never,
      { ...entry(g.did, stone, T1), nullified: true },
      entry(g.did, restored, T2),
    ];
    const doc = await new MethodPlc({
      fetchFn: directoryFor(g.did, entries, documentOf(g.did, g.data)).fetchFn,
    }).resolve(g.did);
    expect(doc.id).toBe(g.did);
  });
});
