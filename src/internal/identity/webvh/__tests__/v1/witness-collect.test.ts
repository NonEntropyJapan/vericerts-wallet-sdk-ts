/**
 * witness proof の収集と `did-witness.json` の生成・更新（コントローラ側 `collectWebVhWitnessProofs`、witness 側
 * `createWebVhWitnessProof` / `assertWebVhCandidateVerifies`）。収集した結果が解決側の検証をそのまま通ることで確かめる。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { WebVhLogEntry, WebVhProof } from '../../codec.js';
import {
  assertWebVhCandidateVerifies,
  collectWebVhWitnessProofs,
  createWebVhWitnessProof,
  updateDidWebVh,
  type WebVhWitnessApprover,
} from '../../method-webvh.js';
import { generateKey, restoreFetch, signEntry } from '../webvh-fixtures.js';
import {
  INVALID_DID,
  resolveWithWitnessFile,
  signedGenesis,
  stateOf,
  witnessKey,
  witnessProofFor,
} from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

type Witness = ReturnType<typeof witnessKey>;

/** 承認する witness の窓口。受け取った依頼と承認可否を記録する。 */
function approver(witness: Witness, options: { approve?: boolean } = {}) {
  const requests: { entry: WebVhLogEntry; previousLog: readonly WebVhLogEntry[] }[] = [];
  const value: WebVhWitnessApprover = {
    id: witness.id,
    approve: async (request) => {
      requests.push(request);
      if (options.approve === false) {
        return undefined;
      }
      // witness 側: 自分が持つ公開済みの Log で候補を検証してから承認する。
      assertWebVhCandidateVerifies(request.previousLog, request.entry);
      return createWebVhWitnessProof(request.entry.versionId, {
        id: witness.id,
        sign: (hashData) => ed25519.sign(hashData, witness.key.secretKey),
      });
    },
  };
  return { value, requests };
}

const asFile = (items: unknown) => JSON.stringify(items);

describe('collectWebVhWitnessProofs', () => {
  it('初版: 閾値ぶんの承認を集め、生成した did-witness.json で解決できる', async () => {
    const [w1, w2, w3] = [witnessKey(), witnessKey(), witnessKey()] as [Witness, Witness, Witness];
    const { did, genesis } = signedGenesis({
      witness: { threshold: 2, witnesses: [w1, w2, w3].map((w) => ({ id: w.id })) },
    });
    const [a1, a2, a3] = [approver(w1), approver(w2, { approve: false }), approver(w3)] as const;
    const file = await collectWebVhWitnessProofs({
      entry: genesis,
      previousLog: [],
      approvers: [a1.value, a2.value, a3.value],
    });
    expect(file.map((item) => item.versionId)).toEqual([genesis.versionId]);
    expect(file[0]?.proof).toHaveLength(2);
    // witness は候補エントリ（コントローラの proof 付き）を受け取る。
    expect(a1.requests[0]?.entry.versionId).toBe(genesis.versionId);
    expect(a1.requests[0]?.entry.proof).toBeDefined();
    await resolveWithWitnessFile(did, [genesis], asFile(file)).result;
  });

  it('更新: 古い proof を剪定し、witness ごとに最新の proof だけを残す。公開済みの版への proof は含意で足りる', async () => {
    const w1 = witnessKey();
    const { key, did, genesis } = signedGenesis({
      witness: { threshold: 1, witnesses: [{ id: w1.id }] },
    });
    const a1 = approver(w1);
    const file1 = await collectWebVhWitnessProofs({
      entry: genesis,
      previousLog: [],
      approvers: [a1.value],
    });
    const v2 = signEntry({ ...nextOf([genesis]), parameters: { updateKeys: [key.multikey] } }, key);
    const file2 = await collectWebVhWitnessProofs({
      entry: v2,
      previousLog: [genesis],
      approvers: [a1.value],
      previousWitnessFile: file1,
    });
    expect(file2.map((item) => item.versionId)).toEqual([v2.versionId]);
    await resolveWithWitnessFile(did, [genesis, v2], asFile(file2)).result;
  });

  it('witness を変える版は変更前の witness に承認を求め、新しい witness は次の版から求める', async () => {
    const [w1, w2] = [witnessKey(), witnessKey()] as [Witness, Witness];
    const { key, did, genesis } = signedGenesis({
      witness: { threshold: 1, witnesses: [{ id: w1.id }] },
    });
    const [a1, a2] = [approver(w1), approver(w2)] as const;
    const file1 = await collectWebVhWitnessProofs({
      entry: genesis,
      previousLog: [],
      approvers: [a1.value],
    });
    const v2 = signEntry(
      nextOf([genesis], { witness: { threshold: 1, witnesses: [{ id: w2.id }] } }),
      key,
    );
    // 変更を宣言する版は、新しい witness だけでは承認できない（旧構成の witness が要る）。
    await expect(
      collectWebVhWitnessProofs({
        entry: v2,
        previousLog: [genesis],
        approvers: [a2.value],
        previousWitnessFile: file1,
      }),
    ).rejects.toThrow(INVALID_DID);
    const file2 = await collectWebVhWitnessProofs({
      entry: v2,
      previousLog: [genesis],
      approvers: [a1.value],
      previousWitnessFile: file1,
    });
    const v3 = signEntry(nextOf([genesis, v2]), key);
    const file3 = await collectWebVhWitnessProofs({
      entry: v3,
      previousLog: [genesis, v2],
      approvers: [a2.value],
      previousWitnessFile: file2,
    });
    // 旧 witness(w1) の proof は v2 のものとして残り、v3 の proof は新 witness(w2)。
    expect(file3.map((item) => item.versionId)).toEqual([v2.versionId, v3.versionId]);
    await resolveWithWitnessFile(did, [genesis, v2, v3], asFile(file3)).result;
  });

  it('承認が閾値に満たない・拒否・例外・偽の proof は収集に数えず、拒否される', async () => {
    const [w1, w2] = [witnessKey(), witnessKey()] as [Witness, Witness];
    const impostor = witnessKey();
    const { genesis } = signedGenesis({
      witness: { threshold: 2, witnesses: [w1, w2].map((w) => ({ id: w.id })) },
    });
    const throwing: WebVhWitnessApprover = {
      id: w2.id,
      approve: async () => {
        throw new Error('network');
      },
    };
    await expect(
      collectWebVhWitnessProofs({
        entry: genesis,
        previousLog: [],
        approvers: [approver(w1).value, throwing],
      }),
    ).rejects.toThrow(INVALID_DID);
    // w2 を名乗って、別の鍵（impostor）で作った proof を返す窓口。
    const forged: WebVhWitnessApprover = {
      id: w2.id,
      approve: ({ entry }) => witnessProofFor(entry.versionId, impostor),
    };
    await expect(
      collectWebVhWitnessProofs({
        entry: genesis,
        previousLog: [],
        approvers: [approver(w1).value, forged],
      }),
    ).rejects.toThrow(INVALID_DID);
    // 別の版の versionId に対する署名を返す窓口。
    const stale: WebVhWitnessApprover = {
      id: w2.id,
      approve: () => witnessProofFor(`1-Qm${'S'.repeat(44)}`, w2),
    };
    await expect(
      collectWebVhWitnessProofs({
        entry: genesis,
        previousLog: [],
        approvers: [approver(w1).value, stale],
      }),
    ).rejects.toThrow(INVALID_DID);
  });

  it('witness を要さない版・構成にない witness の窓口・重複した窓口は拒否される', async () => {
    const w1 = witnessKey();
    const plain = signedGenesis();
    await expect(
      collectWebVhWitnessProofs({
        entry: plain.genesis,
        previousLog: [],
        approvers: [approver(w1).value],
      }),
    ).rejects.toThrow(INVALID_DID);
    const { genesis } = signedGenesis({ witness: { threshold: 1, witnesses: [{ id: w1.id }] } });
    const outsider = approver(witnessKey()).value;
    await expect(
      collectWebVhWitnessProofs({ entry: genesis, previousLog: [], approvers: [outsider] }),
    ).rejects.toThrow(INVALID_DID);
    const a = approver(w1).value;
    await expect(
      collectWebVhWitnessProofs({ entry: genesis, previousLog: [], approvers: [a, a] }),
    ).rejects.toThrow(INVALID_DID);
  });
});

describe('witness 側のヘルパ', () => {
  it('createWebVhWitnessProof は eddsa-jcs-2022 の proof を作り、did:key 以外・不正な署名は拒否する', async () => {
    const w1 = witnessKey();
    const proof = (await witnessProofFor('1-x', w1)) as WebVhProof;
    expect(proof).toMatchObject({
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      proofPurpose: 'assertionMethod',
      verificationMethod: `${w1.id}#${w1.id.slice('did:key:'.length)}`,
    });
    await expect(
      createWebVhWitnessProof('1-x', { id: 'did:web:example.com', sign: () => new Uint8Array(64) }),
    ).rejects.toThrow(INVALID_DID);
    await expect(
      createWebVhWitnessProof('1-x', { id: w1.id, sign: () => new Uint8Array(10) }),
    ).rejects.toThrow(INVALID_DID);
  });

  it('assertWebVhCandidateVerifies: 検証できない候補（署名・entryHash 不正）は拒否する', async () => {
    const { key, genesis } = signedGenesis();
    const good = signEntry(nextOf([genesis]), key);
    expect(() => assertWebVhCandidateVerifies([genesis], good)).not.toThrow();
    const other = generateKey();
    const badSig = signEntry(nextOf([genesis]), other);
    expect(() => assertWebVhCandidateVerifies([genesis], badSig)).toThrow(INVALID_DID);
    expect(() =>
      assertWebVhCandidateVerifies([genesis], { ...good, versionId: `2-Qm${'W'.repeat(44)}` }),
    ).toThrow(INVALID_DID);
  });
});

/** `updateDidWebVh` 由来の次版（署名前）。 */
function nextOf(
  log: readonly WebVhLogEntry[],
  options: Record<string, unknown> = {},
): WebVhLogEntry {
  const last = log[log.length - 1] as WebVhLogEntry;
  return updateDidWebVh({ previousLog: log, state: stateOf(last.state.id), ...options });
}
