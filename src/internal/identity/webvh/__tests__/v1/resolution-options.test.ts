/**
 * 解決オプション（versionId / versionTime / versionNumber）の選択規則（did:webvh v1.0、spec: Read (Resolve) の
 * 「Produce the requested DIDDoc」）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { restoreFetch } from '../webvh-fixtures.js';
import { appendSigned, INVALID_DID, resolveLog, signedGenesis, stateOf } from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

/** 3 版のログ（各版の state は alsoKnownAs で区別する）。 */
function threeVersions() {
  const { key, did, genesis } = signedGenesis();
  const v2 = appendSigned([genesis], key, {
    state: stateOf(did, { alsoKnownAs: ['https://two.example'] }),
  });
  const v3 = appendSigned([genesis, v2], key, {
    state: stateOf(did, { alsoKnownAs: ['https://three.example'] }),
  });
  return { did, log: [genesis, v2, v3] };
}

describe('解決オプション', () => {
  it('versionNumber は版番号（versionId の `-` の前の整数）の版を返す', async () => {
    const { did, log } = threeVersions();
    const second = await resolveLog(did, log, { versionNumber: 2 });
    expect(second.document.alsoKnownAs).toEqual(['https://two.example']);
    expect(second.metadata.versionId).toBe(log[1]?.versionId as string);
    // メタデータの updated / created は DID 全体のもの。
    expect(second.metadata.updated).toBe(log[2]?.versionTime as string);
  });

  it.each([
    0,
    4,
    -1,
    1.5,
    Number.NaN,
  ])('範囲外・整数でない versionNumber（%p）は拒否される', async (versionNumber) => {
    const { did, log } = threeVersions();
    await expect(resolveLog(did, log, { versionNumber })).rejects.toThrow(INVALID_DID);
  });

  it('versionId は完全一致の版を返し、一致する版がなければ拒否される', async () => {
    const { did, log } = threeVersions();
    const first = await resolveLog(did, log, { versionId: log[0]?.versionId as string });
    expect(first.metadata.versionId).toBe(log[0]?.versionId as string);
    await expect(resolveLog(did, log, { versionId: `2-Qm${'Z'.repeat(44)}` })).rejects.toThrow(
      INVALID_DID,
    );
    await expect(resolveLog(did, log, { versionId: '2' })).rejects.toThrow(INVALID_DID);
  });

  it('versionTime は、その時刻以前で最新の版（その時刻に有効だった版）を返し、DID の作成前なら拒否される', async () => {
    const { did, log } = threeVersions();
    const [v1, v2] = log;
    const between = new Date(
      (Date.parse(v2?.versionTime as string) + Date.parse(log[2]?.versionTime as string)) / 2,
    ).toISOString();
    expect(
      (await resolveLog(did, log, { versionTime: v2?.versionTime as string })).metadata.versionId,
    ).toBe(v2?.versionId as string);
    expect((await resolveLog(did, log, { versionTime: between })).metadata.versionId).toBe(
      v2?.versionId as string,
    );
    const beforeCreation = new Date(Date.parse(v1?.versionTime as string) - 1000).toISOString();
    await expect(resolveLog(did, log, { versionTime: beforeCreation })).rejects.toThrow(
      INVALID_DID,
    );
    await expect(resolveLog(did, log, { versionTime: 'yesterday' })).rejects.toThrow(INVALID_DID);
  });

  it('複数のオプションを同時に指定すると拒否される', async () => {
    const { did, log } = threeVersions();
    await expect(
      resolveLog(did, log, { versionNumber: 1, versionId: log[0]?.versionId as string }),
    ).rejects.toThrow(INVALID_DID);
  });
});
