/**
 * 解決の内部フック `beforeWitnessFile`。拡張の in-flight 予算が、witness を使う解決だけ
 * `did-witness.json` を取得する直前に追加の取得ぶんを確保するために使う（`resolveDidWebVhHooked`。バレル非公開）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { createWebVhAttemptLedger, resolveDidWebVhHooked } from '../../resolve.js';
import { restoreFetch } from '../webvh-fixtures.js';
import {
  appendSigned,
  mockWitnessHost,
  signedGenesis,
  witnessKey,
  witnessProofFor,
} from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

const LOG_URL = 'https://vericerts.io/.well-known/did.jsonl';
const WITNESS_URL = 'https://vericerts.io/.well-known/did-witness.json';

async function witnessedLog() {
  const w1 = witnessKey();
  const { key, did, genesis } = signedGenesis({
    witness: { threshold: 1, witnesses: [{ id: w1.id }] },
  });
  const v2 = appendSigned([genesis], key);
  const file = JSON.stringify([
    { versionId: v2.versionId, proof: [await witnessProofFor(v2.versionId, w1)] },
  ]);
  return { did, log: [genesis, v2], file };
}

describe('beforeWitnessFile', () => {
  it('witness が必要な Log では、DID Log の取得のあと・did-witness.json の取得の前に 1 回だけ呼ばれる', async () => {
    const { did, log, file } = await witnessedLog();
    const requested = mockWitnessHost(log, file);
    const seenAtCall: string[][] = [];

    const document = await resolveDidWebVhHooked(did, undefined, {
      ledger: createWebVhAttemptLedger(),
      beforeWitnessFile: () => {
        seenAtCall.push([...requested]);
      },
    });

    expect(document.id).toBe(did);
    expect(seenAtCall).toEqual([[LOG_URL]]);
    expect(requested).toEqual([LOG_URL, WITNESS_URL]);
  });

  it('witness を使わない Log では呼ばれず、取得は DID Log の 1 回だけ', async () => {
    const { key, did, genesis } = signedGenesis();
    const log = [genesis, appendSigned([genesis], key)];
    const requested = mockWitnessHost(log, undefined);
    let called = 0;

    await resolveDidWebVhHooked(did, undefined, {
      ledger: createWebVhAttemptLedger(),
      beforeWitnessFile: () => {
        called += 1;
      },
    });

    expect(called).toBe(0);
    expect(requested).toEqual([LOG_URL]);
  });

  it('フックが例外を投げると、その例外のまま解決が失敗し、did-witness.json は取得されない', async () => {
    const { did, log, file } = await witnessedLog();
    const requested = mockWitnessHost(log, file);
    const marker = new Error('hook-refused');

    await expect(
      resolveDidWebVhHooked(did, undefined, {
        ledger: createWebVhAttemptLedger(),
        beforeWitnessFile: () => {
          throw marker;
        },
      }),
    ).rejects.toBe(marker);
    expect(requested).toEqual([LOG_URL]);
  });

  it('フックが無ければ従来どおり解決できる（フックは任意）', async () => {
    const { did, log, file } = await witnessedLog();
    const requested = mockWitnessHost(log, file);

    expect(
      (await resolveDidWebVhHooked(did, undefined, { ledger: createWebVhAttemptLedger() })).id,
    ).toBe(did);
    expect(requested).toEqual([LOG_URL, WITNESS_URL]);
  });
});
