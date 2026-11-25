/**
 * `did-witness.json` の取得と検証にかかる上限（DoS 対策）。取得先は受領した VC の `iss` 由来で
 * 攻撃者が選べるので、署名検証・パースより前に件数・サイズだけで拒否する。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { MAX_DOCUMENT_BYTES } from '../../../../http/body-limit.js';
import {
  createResolutionWorkBudget,
  WORK_UNITS_PER_SIGNATURE,
} from '../../../resolution-budget.js';
import {
  MAX_WITNESS_FILE_ITEMS,
  MAX_WITNESS_FILE_PROOFS,
  MAX_WITNESS_PROOFS_PER_ITEM,
  MAX_WITNESSES_PER_ENTRY,
} from '../../limits.js';
import { parseWitnessFile } from '../../witness/file.js';
import { restoreFetch } from '../webvh-fixtures.js';
import {
  INVALID_DID,
  resolveWithWitnessFile,
  signedGenesis,
  witnessKey,
  witnessProofFor,
} from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

const TOO_LARGE = { code: '2001', context: { reason: 'did_log_too_large' } };

describe('parseWitnessFile の上限', () => {
  it('項目数が上限ちょうどなら通り、超えると JSON の中身を見ずに拒否される', () => {
    const item = '{"versionId":"1-x"}';
    const at = `[${Array(MAX_WITNESS_FILE_ITEMS).fill(item).join(',')}]`;
    expect(parseWitnessFile(at)).toHaveLength(MAX_WITNESS_FILE_ITEMS);
    const over = `[${Array(MAX_WITNESS_FILE_ITEMS + 1)
      .fill(item)
      .join(',')}]`;
    expect(() => parseWitnessFile(over)).toThrow(expect.objectContaining(TOO_LARGE));
  });

  it('1 項目あたりの proof 数・ファイル全体の proof 数が上限を超えると拒否される', () => {
    const proofs = (n: number) => Array(n).fill({ proofValue: 'z' });
    const okItem = { versionId: '1-x', proof: proofs(MAX_WITNESS_PROOFS_PER_ITEM) };
    expect(parseWitnessFile(JSON.stringify([okItem]))).toHaveLength(1);
    expect(() =>
      parseWitnessFile(
        JSON.stringify([{ versionId: '1-x', proof: proofs(MAX_WITNESS_PROOFS_PER_ITEM + 1) }]),
      ),
    ).toThrow(expect.objectContaining(TOO_LARGE));
    const many = Array.from(
      { length: Math.ceil(MAX_WITNESS_FILE_PROOFS / MAX_WITNESS_PROOFS_PER_ITEM) + 1 },
      (_, i) => ({
        versionId: `${i + 1}-x`,
        proof: proofs(MAX_WITNESS_PROOFS_PER_ITEM),
      }),
    );
    expect(() => parseWitnessFile(JSON.stringify(many))).toThrow(
      expect.objectContaining(TOO_LARGE),
    );
  });

  it('proof を省略した項目は空の proof として読む', () => {
    expect(parseWitnessFile('[{"versionId":"1-x"}]')).toEqual([{ versionId: '1-x', proof: [] }]);
  });

  it('Object.prototype の汚染値を項目の versionId / proof として拾わない', () => {
    const proto = Object.prototype as unknown as Record<string, unknown>;
    proto.versionId = '1-polluted';
    proto.proof = [{ proofValue: 'z-polluted' }];
    try {
      expect(() => parseWitnessFile('[{}]')).toThrow(INVALID_DID);
      expect(parseWitnessFile('[{"versionId":"1-x"}]')).toEqual([{ versionId: '1-x', proof: [] }]);
    } finally {
      delete proto.versionId;
      delete proto.proof;
    }
  });
});

describe('解決時の上限', () => {
  it('did-witness.json の本文が 1 MiB を超えると、パースせず取得失敗（2003）として拒否される', async () => {
    const w1 = witnessKey();
    const { did, genesis } = signedGenesis({
      witness: { threshold: 1, witnesses: [{ id: w1.id }] },
    });
    const huge = `[${'{"versionId":"1-x"},'.repeat(Math.ceil(MAX_DOCUMENT_BYTES / 19) + 1)}{}]`;
    await expect(resolveWithWitnessFile(did, [genesis], huge).result).rejects.toMatchObject({
      code: '2003',
    });
  });

  it('witness の件数が上限を超える構成は、検証前に拒否される', () => {
    const witnesses = Array.from({ length: MAX_WITNESSES_PER_ENTRY + 1 }, () => ({
      id: witnessKey().id,
    }));
    expect(() => signedGenesis({ witness: { threshold: 1, witnesses } })).toThrow(
      expect.objectContaining(TOO_LARGE),
    );
  });

  it('不正な proof を並べて署名検証を増やす攻撃は、スコープの仕事量予算で打ち切られる', async () => {
    const w1 = witnessKey();
    const { did, genesis } = signedGenesis({
      witness: { threshold: 1, witnesses: [{ id: w1.id }] },
    });
    const valid = await witnessProofFor(genesis.versionId, w1);
    const forged = Array.from({ length: 20 }, () => ({
      ...valid,
      proofValue: `z${'2'.repeat(60)}`,
    }));
    const file = JSON.stringify([{ versionId: genesis.versionId, proof: forged }]);
    // 予算: Log の署名 1 回 + witness proof の署名 3 回ぶん。
    const scope = createResolutionWorkBudget(4 * WORK_UNITS_PER_SIGNATURE);
    const { result } = resolveWithWitnessFile(did, [genesis], file, undefined, scope);
    await expect(result).rejects.toMatchObject({
      code: '2001',
      context: { reason: 'resolution_work_limit' },
    });
    expect(scope.remaining).toBeLessThan(WORK_UNITS_PER_SIGNATURE);
  });

  it('did-witness.json の本文も、スコープの本文量の予算に計上される', async () => {
    const w1 = witnessKey();
    const { did, genesis } = signedGenesis({
      witness: { threshold: 1, witnesses: [{ id: w1.id }] },
    });
    const file = JSON.stringify([
      { versionId: genesis.versionId, proof: [await witnessProofFor(genesis.versionId, w1)] },
    ]);
    const logLength = JSON.stringify(genesis).length;
    const scope = createResolutionWorkBudget(undefined, logLength + 10);
    const { result } = resolveWithWitnessFile(did, [genesis], file, undefined, scope);
    await expect(result).rejects.toMatchObject({
      code: '2001',
      context: { reason: 'resolution_work_limit' },
    });
  });
});
