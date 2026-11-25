/**
 * SLIP-0039 公式テストベクタ（satoshilabs/slips の vectors.json = trezor/python-shamir-mnemonic
 * 同梱データを複製したもの、`slip39-vectors.json`）による低レイヤープリミティブの相互運用性検証。
 *
 * 本 SDK の公開 API（createShamirShares / recoverFromShamirShares）は単一グループ構成のみを
 * 扱うが、ここでは gf256 / cipher / share / rs1024 の各プリミティブが仕様どおり実装されている
 * ことを、複数グループ構成を含む全 45 ベクタに対する汎用 Combine（spec §Combining the shares）
 * で検証する。テストベクタの検証パスワードは spec 記載のとおり "TREZOR" 固定。
 */

import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { bytesToHex } from '@noble/hashes/utils.js';
import { decryptMasterSecret } from '../cipher.js';
import { recoverSecret } from '../shamir-core.js';
import { type Share, shareFromMnemonic } from '../share.js';

type Vector = [
  description: string,
  mnemonics: string[],
  expectedSecretHex: string,
  expectedXprv: string,
];

const VECTORS = JSON.parse(
  readFileSync(new URL('./slip39-vectors.json', import.meta.url), 'utf8'),
) as Vector[];

const PASSPHRASE = new TextEncoder().encode('TREZOR');

/**
 * spec §Combining the shares の汎用（複数グループ対応）実装。テスト専用。
 * 本番コード（shamir/index.ts）は単一グループのみをサポートするため、ここでしか使わない。
 */
function combine(mnemonics: readonly string[], passphrase: Uint8Array): Uint8Array {
  if (mnemonics.length === 0) {
    throw new Error('empty mnemonic list');
  }
  const shares = mnemonics.map(shareFromMnemonic);

  const first = shares[0];
  if (first === undefined) {
    throw new Error('empty mnemonic list');
  }
  for (const share of shares) {
    if (
      share.identifier !== first.identifier ||
      share.extendable !== first.extendable ||
      share.iterationExponent !== first.iterationExponent ||
      share.groupThreshold !== first.groupThreshold ||
      share.groupCount !== first.groupCount
    ) {
      throw new Error('mismatching common parameters');
    }
  }

  const byGroup = new Map<number, Share[]>();
  for (const share of shares) {
    const group = byGroup.get(share.groupIndex) ?? [];
    group.push(share);
    byGroup.set(share.groupIndex, group);
  }

  if (byGroup.size < first.groupThreshold) {
    throw new Error('insufficient number of groups');
  }
  if (byGroup.size !== first.groupThreshold) {
    throw new Error('wrong number of groups');
  }

  const groupShares = [...byGroup.entries()].map(([groupIndex, members]) => {
    const firstMember = members[0];
    if (firstMember === undefined) {
      throw new Error('empty group');
    }
    const memberThreshold = firstMember.memberThreshold;
    const memberIndices = new Set(members.map((m) => m.index));
    if (
      members.some((m) => m.memberThreshold !== memberThreshold) ||
      memberIndices.size !== members.length ||
      members.length !== memberThreshold
    ) {
      throw new Error('wrong number or mismatching members in group');
    }
    const secret = recoverSecret(
      memberThreshold,
      members.map((m) => ({ x: m.index, data: m.value })),
    );
    return { x: groupIndex, data: secret };
  });

  const ems = recoverSecret(first.groupThreshold, groupShares);
  return decryptMasterSecret(
    ems,
    passphrase,
    first.iterationExponent,
    first.identifier,
    first.extendable,
  );
}

describe('SLIP-0039 公式テストベクタ (satoshilabs/slips vectors.json)', () => {
  test.each(VECTORS)('%s', (_description, mnemonics, expectedSecretHex) => {
    if (expectedSecretHex === '') {
      expect(() => combine(mnemonics, PASSPHRASE)).toThrow();
      return;
    }
    const secret = combine(mnemonics, PASSPHRASE);
    expect(bytesToHex(secret)).toBe(expectedSecretHex);
  });
});
