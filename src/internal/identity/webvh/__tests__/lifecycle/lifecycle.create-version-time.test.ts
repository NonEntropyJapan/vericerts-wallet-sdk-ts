/**
 * createDidWebVh が `verifyChain` の index 0 と同じ versionTime 規則で拒否すること。
 *
 * 以前は update 側だけを直したため、create は未来日時・解釈不能な versionTime を黙って受理し、
 * 署名・公開後に DID 全体が解決不能になる初版ログを生成できた（SCID が versionTime を含むため
 * 公開後の訂正もできない）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { createDidWebVh } from '../../method-webvh.js';
import { verifyChain } from '../../verify.js';
import { generateKey, signEntry } from '../webvh-fixtures.js';

const INVALID_DID = new VericertsError(ErrorCodes.INVALID_DID);
const MINUTE = 60 * 1000;

describe('createDidWebVh の versionTime', () => {
  it('未来（+5 分超）・ISO 8601 でない versionTime は INVALID_DID', () => {
    const key = generateKey();
    const future = new Date(Date.now() + 10 * MINUTE).toISOString();
    for (const versionTime of [
      future,
      '2099-01-01T00:00:00Z',
      'not-a-date',
      '2026-01-01 00:00:00',
    ]) {
      expect(() =>
        createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey], versionTime }),
      ).toThrow(INVALID_DID);
    }
  });

  it('既定値・過去・クロックずれ許容内（+1 分）の versionTime は受理され、verifyChain も通る', () => {
    const key = generateKey();
    const explicit = [
      undefined,
      '2026-01-01T00:00:00Z',
      new Date(Date.now() + MINUTE).toISOString(),
    ];
    for (const versionTime of explicit) {
      const { did, logEntry } = createDidWebVh({
        domain: 'vericerts.io',
        updateKeys: [key.multikey],
        ...(versionTime === undefined ? {} : { versionTime }),
      });
      if (versionTime !== undefined) expect(logEntry.versionTime).toBe(versionTime);
      const scid = did.split(':')[2] as string;
      expect(() => verifyChain([signEntry(logEntry, key)], did, scid)).not.toThrow();
    }
  });

  // spec Read (Resolve) 4。versionTime は UTC を明示する `Z`（または `+00:00`）に限る。
  it('UTC 以外のオフセット・ゾーン指定なしの versionTime は INVALID_DID（同じ時刻でも）、`+00:00` / `Z` は受理される', () => {
    const key = generateKey();
    const instant = Date.now() - MINUTE;
    const utc = new Date(instant).toISOString();
    const create = (versionTime: string) =>
      createDidWebVh({ domain: 'vericerts.io', updateKeys: [key.multikey], versionTime });
    const plus9 = new Date(instant + 9 * 60 * MINUTE).toISOString().replace('Z', '+09:00');

    for (const versionTime of [plus9, utc.replace('Z', '')]) {
      expect(() => create(versionTime)).toThrow(INVALID_DID);
    }
    for (const versionTime of [utc, utc.replace('Z', '+00:00')]) {
      expect(create(versionTime).logEntry.versionTime).toBe(versionTime);
    }
  });
});
