/**
 * `MethodPlc.resolve` の `ResolutionWorkBudget` への計上と、`MethodPlc` の `2002` / 登録 / 設定。
 *
 * 取得は `fetchFn` 注入のモックで、実ネットワークには接続しない。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { createResolutionWorkBudget, WORK_UNITS_PER_SIGNATURE } from '../../resolution-budget.js';
import { Resolver } from '../../resolver.js';
import { MethodPlc } from '../method-plc.js';
import {
  dataOf,
  directoryFor,
  documentOf,
  entry,
  expectVericertsError,
  genesis,
  makeKey,
  nextOperation,
} from './plc.fixtures.js';

const T1 = '2026-10-01T01:00:00.000Z';

describe('MethodPlc.resolve — ResolutionWorkBudget の計上', () => {
  it('署名検証 1 回ごとに WORK_UNITS_PER_SIGNATURE を計上し、本文の文字数を計上する', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const op = await nextOperation(g.did, g.entries[0] as never, g.data, key);
    const entries = [...g.entries, entry(g.did, op, T1)];
    const doc = documentOf(g.did, g.data);
    const dir = directoryFor(g.did, entries, doc);
    const budget = createResolutionWorkBudget();
    await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did, budget);
    const used = createResolutionWorkBudget().remaining - budget.remaining;
    // ジェネシス（自身の鍵 1 回）+ 後続（直前の rotationKeys の先頭で 1 回）
    expect(used).toBe(2 * WORK_UNITS_PER_SIGNATURE);
    const bodyChars = JSON.stringify(entries).length + JSON.stringify(doc).length;
    expect(createResolutionWorkBudget().remainingBodyLength - budget.remainingBodyLength).toBe(
      bodyChars,
    );
  });

  it('優先度の低い鍵で署名された操作は、試した鍵の数だけ計上する', async () => {
    const high = makeKey();
    const low = makeKey('P-256');
    const g = await genesis(high, dataOf([high, low]));
    const op = await nextOperation(g.did, g.entries[0] as never, g.data, low);
    const dir = directoryFor(
      g.did,
      [...g.entries, entry(g.did, op, T1)],
      documentOf(g.did, g.data),
    );
    const budget = createResolutionWorkBudget();
    await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did, budget);
    // ジェネシス: 先頭鍵で 1 回。後続: 先頭鍵で失敗 + 2 番目の鍵で成功 = 2 回。
    expect(createResolutionWorkBudget().remaining - budget.remaining).toBe(
      3 * WORK_UNITS_PER_SIGNATURE,
    );
  });

  it('仕事量が尽きると署名検証の途中で 2001（resolution_work_limit）', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const op = await nextOperation(g.did, g.entries[0] as never, g.data, key);
    const dir = directoryFor(
      g.did,
      [...g.entries, entry(g.did, op, T1)],
      documentOf(g.did, g.data),
    );
    const budget = createResolutionWorkBudget(WORK_UNITS_PER_SIGNATURE);
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did, budget),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
  });

  it('本文量が尽きたスコープでは取得を始めず、超える本文はパースの前に 2001', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const dir = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    const exhausted = createResolutionWorkBudget(undefined, 0);
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did, exhausted),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
    expect(dir.requests).toHaveLength(0);
    const small = createResolutionWorkBudget(undefined, 10);
    await expectVericertsError(
      () => new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did, small),
      ErrorCodes.INVALID_DID,
      'resolution_work_limit',
    );
  });

  it('スコープ外の単独解決（scope なし）は計上しない', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const dir = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did);
  });
});

describe('MethodPlc — その他', () => {
  it('method() は plc、create / update / deactivate は 2002', async () => {
    const method = new MethodPlc();
    expect(method.method()).toBe('plc');
    await expectVericertsError(() => method.create({} as never), ErrorCodes.METHOD_NOT_SUPPORTED);
    await expectVericertsError(
      () => method.update('did:plc:ewvi7nxzyoun6zhxrhs64oiz', {} as never),
      ErrorCodes.METHOD_NOT_SUPPORTED,
    );
    await expectVericertsError(
      () => method.deactivate('did:plc:ewvi7nxzyoun6zhxrhs64oiz'),
      ErrorCodes.METHOD_NOT_SUPPORTED,
    );
  });

  it('登録した Resolver 経由の解決は 2002 で拒否されない', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const dir = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    const resolver = new Resolver();
    resolver.register(new MethodPlc({ fetchFn: dir.fetchFn }));
    expect((await resolver.resolve(g.did)).id).toBe(g.did);
  });

  it('relationshipsForKeys に不正な検証関係があれば構築時に 2001（invalid_relationships）', async () => {
    for (const bad of [{ atproto: ['capabilityDelegation'] }, { atproto: 'authentication' }, 'x']) {
      await expectVericertsError(
        async () => new MethodPlc({ relationshipsForKeys: bad as never }),
        ErrorCodes.INVALID_DID,
        'invalid_relationships',
      );
    }
  });

  it('Object.prototype 汚染は設定値に化けない', async () => {
    const key = makeKey();
    const g = await genesis(key);
    const dir = directoryFor(g.did, g.entries, documentOf(g.did, g.data));
    const proto = Object.prototype as Record<string, unknown>;
    proto.relationshipsForKeys = { atproto: ['assertionMethod'] };
    proto.directoryUrl = 'https://evil.example';
    try {
      const doc = await new MethodPlc({ fetchFn: dir.fetchFn }).resolve(g.did);
      expect(doc.assertionMethod).toEqual([]);
    } finally {
      delete proto.relationshipsForKeys;
      delete proto.directoryUrl;
    }
  });
});
