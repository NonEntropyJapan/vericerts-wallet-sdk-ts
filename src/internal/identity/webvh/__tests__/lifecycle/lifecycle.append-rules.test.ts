/**
 * updateDidWebVh が `verifyChain` と同じ追記規則で拒否すること。
 *
 * 以前は検証側だけを厳格化したため、ビルダーは失効行への追記や前版以前・未来の
 * versionTime を黙って受理し、署名・公開後に DID 全体が解決不能になるログを生成できた。
 * 生成時に同じ規則で INVALID_DID を返す。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { createDidWebVh, updateDidWebVh } from '../../method-webvh.js';
import { verifyChain } from '../../verify.js';
import { generateKey, signEntry } from '../webvh-fixtures.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);
const MINUTE = 60 * 1000;

/** 生成済み初版（署名付き）と、失効行を含む署名済み 2 行ログを返すフィクスチャ。 */
function webvhFixture() {
  const key = generateKey();
  const { did, logEntry } = createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey] });
  const genesis = signEntry(logEntry, key);
  const deactivated = signEntry(
    updateDidWebVh({ previousLog: [genesis], state: { ...genesis.state }, deactivated: true }),
    key,
  );
  return { key, did, genesis, deactivated };
}

describe('updateDidWebVh の追記規則', () => {
  it('失効行への追記は INVALID_DID', () => {
    const { genesis, deactivated } = webvhFixture();
    expect(() =>
      updateDidWebVh({ previousLog: [genesis, deactivated], state: { ...genesis.state } }),
    ).toThrow(INVALID_DID);
  });

  it('前版と同時刻・過去の versionTime は INVALID_DID', () => {
    const { genesis } = webvhFixture();
    for (const versionTime of [genesis.versionTime, '2000-01-01T00:00:00Z']) {
      expect(() =>
        updateDidWebVh({ previousLog: [genesis], state: { ...genesis.state }, versionTime }),
      ).toThrow(INVALID_DID);
    }
  });

  it('未来（+5 分超）・ISO 8601 でない versionTime は INVALID_DID', () => {
    const { genesis } = webvhFixture();
    const future = new Date(Date.now() + 10 * MINUTE).toISOString();
    for (const versionTime of [future, 'not-a-date', '2026-01-01 00:00:00']) {
      expect(() =>
        updateDidWebVh({ previousLog: [genesis], state: { ...genesis.state }, versionTime }),
      ).toThrow(INVALID_DID);
    }
  });

  it('クロックずれ許容内（+1 分）の versionTime は受理され、verifyChain も通る', () => {
    const { key, did, genesis } = webvhFixture();
    const versionTime = new Date(Date.now() + MINUTE).toISOString();
    const v2 = updateDidWebVh({ previousLog: [genesis], state: { ...genesis.state }, versionTime });
    expect(v2.versionTime).toBe(versionTime);
    const scid = did.split(':')[2] as string;
    expect(() => verifyChain([genesis, signEntry(v2, key)], did, scid)).not.toThrow();
  });

  // spec Read (Resolve) 4。versionTime は UTC を明示する `Z`（または `+00:00`）に限る。
  it('UTC 以外のオフセット・ゾーン指定なしの versionTime は INVALID_DID（同じ時刻でも）、`+00:00` / `Z` は受理される', () => {
    const { genesis } = webvhFixture();
    const instant = Date.now() + MINUTE;
    const utc = new Date(instant).toISOString();
    const update = (versionTime: string) =>
      updateDidWebVh({ previousLog: [genesis], state: { ...genesis.state }, versionTime });
    const plus9 = new Date(instant + 9 * 60 * MINUTE).toISOString().replace('Z', '+09:00');

    for (const versionTime of [plus9, utc.replace('Z', '')]) {
      expect(() => update(versionTime)).toThrow(INVALID_DID);
    }
    for (const versionTime of [utc, utc.replace('Z', '+00:00')]) {
      expect(update(versionTime).versionTime).toBe(versionTime);
    }
  });
});
