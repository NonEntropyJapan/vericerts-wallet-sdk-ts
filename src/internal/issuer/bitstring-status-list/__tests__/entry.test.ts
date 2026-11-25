/**
 * Bitstring Status List のエントリとリストの突合（`checkBitstringStatus`）のユニットテスト。
 *
 * 検証内容: エントリの `type` / `statusPurpose` / `statusSize` がリストと食い違う・`statusListIndex` が不正または
 * 範囲外・`statusMessage` が不正なら、すべて 3002 で拒否する（取り違えたビットが「失効していない」と読まれない）。
 * エントリは外部入力なので、継承プロパティ（`Object.prototype` 汚染）は値として読まない。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, type VericertsError } from '../../../errors.js';
import {
  BitstringStatusList,
  type BitstringStatusListEntry,
  checkBitstringStatus,
  createBitstringStatusListEntry,
} from '../index.js';

const URL1 = 'https://issuer.example/status/1';

function expectCode(fn: () => unknown, code: ErrorCode): void {
  try {
    fn();
  } catch (e) {
    expect((e as VericertsError).code).toBe(code);
    return;
  }
  throw new Error('expected throw');
}

describe('エントリとリストの突合（checkBitstringStatus）', () => {
  const list = BitstringStatusList.create('revocation', 1, 131_072);
  const base: BitstringStatusListEntry = createBitstringStatusListEntry(list, 5, URL1);

  it.each([
    ['type 違い', { ...base, type: 'SomethingElse' }],
    ['statusPurpose 違い', { ...base, statusPurpose: 'suspension' }],
    ['statusSize 不一致', { ...base, statusSize: 2 }],
    ['index が数字以外', { ...base, statusListIndex: '1x' }],
    ['index が空', { ...base, statusListIndex: '' }],
    ['index が負', { ...base, statusListIndex: '-1' }],
    ['index が数値型', { ...base, statusListIndex: 5 }],
    ['index が範囲外', { ...base, statusListIndex: '131072' }],
    ['index が安全整数を超える', { ...base, statusListIndex: '99999999999999999999' }],
    ['statusMessage が配列でない', { ...base, statusMessage: 'x' }],
  ])('%s は 3002', (_label, entry) => {
    expectCode(() => checkBitstringStatus(entry, list), ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('entry がオブジェクトでない（null / 配列 / 文字列）なら 3002', () => {
    for (const bad of [null, [], 'x', 1]) {
      expectCode(() => checkBitstringStatus(bad, list), ErrorCodes.VC_SCHEMA_INVALID);
    }
  });

  it('statusSize を省略したエントリは 1 ビット以外のリストに対して 3002', () => {
    const message = BitstringStatusList.create('message', 2, 65_536);
    const entry = { ...createBitstringStatusListEntry(message, 1, URL1), statusSize: undefined };

    expectCode(() => checkBitstringStatus(entry, message), ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('statusMessage の要素が {status, message} 文字列でなければ 3002', () => {
    const message = BitstringStatusList.create('message', 2, 65_536);
    const entry = {
      ...createBitstringStatusListEntry(message, 1, URL1),
      statusMessage: [{ status: '0x0' }],
    };

    expectCode(() => checkBitstringStatus(entry, message), ErrorCodes.VC_SCHEMA_INVALID);
  });

  it('継承プロパティ（Object.prototype 汚染）は entry の値として読まない', () => {
    const polluted = { statusSize: 2 };
    const proto = Object.prototype as unknown as Record<string, unknown>;
    proto.statusSize = polluted.statusSize;
    try {
      // statusSize を持たない正当なエントリは、汚染下でも 1 ビットのリストに対して成立する。
      expect(checkBitstringStatus(base, list).value).toBe(0);
    } finally {
      delete proto.statusSize;
    }
  });
});
