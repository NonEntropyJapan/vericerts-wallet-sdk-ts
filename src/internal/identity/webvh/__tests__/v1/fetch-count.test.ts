/**
 * 1 回の did:webvh 解決（SDK の `resolve()` 1 回）が行う本文取得の回数。
 *
 * 拡張の in-flight 予算は 1 MiB から始め、
 * witness が必要なとき（DID Log の検証後）だけ、`did-witness.json` の取得の直前に追加の 1 MiB を確保する。この前提は、SDK の
 * 1 回の `resolve()` が取得するのは DID Log と（witness を使うときだけ）`did-witness.json` の高々 2 回で、witness なしは 1 回だけ、
 * ということである。この回数は SDK の公開定数ではなく、増えると拡張の確保が足りなくなるため、版の数・解決オプションに依らず
 * ここで固定する。なお、競合で追加確保が取れなかったとき、拡張は 1 回分を手放して最初から 2 回分を取り直して解決をやり直す。
 * そのため拡張側の 1 つの `resolve()` 呼び出しは、最大で DID Log 2 回 + `did-witness.json` 1 回の取得になり得る
 * （拡張による再試行を含む取得回数）。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { restoreFetch } from '../webvh-fixtures.js';
import {
  appendSigned,
  resolveWithWitnessFile,
  signedGenesis,
  witnessKey,
  witnessProofFor,
} from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

const WELL_KNOWN = 'https://vericerts.io/.well-known/';

describe('did:webvh の 1 回の解決の取得回数', () => {
  it('witness を使う DID は、版の数・解決オプションに依らず DID Log と did-witness.json の 2 回だけ取得する', async () => {
    const w1 = witnessKey();
    const { key, did, genesis } = signedGenesis({
      witness: { threshold: 1, witnesses: [{ id: w1.id }] },
    });
    const v2 = appendSigned([genesis], key);
    const v3 = appendSigned([genesis, v2], key);
    const proof = await witnessProofFor(v3.versionId, w1);
    const file = JSON.stringify([{ versionId: v3.versionId, proof: [proof] }]);

    for (const options of [undefined, { versionNumber: 1 }, { versionId: v2.versionId }]) {
      const { requested, result } = resolveWithWitnessFile(did, [genesis, v2, v3], file, options);
      await result;
      expect(requested).toEqual([`${WELL_KNOWN}did.jsonl`, `${WELL_KNOWN}did-witness.json`]);
    }
  });

  it('witness を使わない DID は DID Log の 1 回だけ取得する', async () => {
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key);
    const { requested, result } = resolveWithWitnessFile(did, [genesis, v2], undefined);
    await result;
    expect(requested).toEqual([`${WELL_KNOWN}did.jsonl`]);
  });
});
