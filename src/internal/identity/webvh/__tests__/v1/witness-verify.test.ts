/**
 * witness proof の検証（did:webvh v1.0、spec: DID Witnesses 全般 — Witness Threshold Algorithm、The Witness Proofs File、
 * Verifying Witness Proofs During Resolution）。`did-witness.json` は実際に署名した proof で組み立てる。
 */

import { afterEach, describe, expect, it } from 'bun:test';
import type { WebVhLogEntry, WebVhProof } from '../../codec.js';
import { restoreFetch, signEntry } from '../webvh-fixtures.js';
import {
  appendSigned,
  INVALID_DID,
  resolveWithWitnessFile,
  signedGenesis,
  witnessKey,
  witnessProofFor,
} from './log-builders.js';

afterEach(() => {
  restoreFetch();
});

type Witness = ReturnType<typeof witnessKey>;

/** `witness` 付きの初版と、その鍵・witness。 */
function witnessedGenesis(threshold: number, witnesses: Witness[]) {
  return signedGenesis({
    witness: { threshold, witnesses: witnesses.map((w) => ({ id: w.id })) },
  });
}

/** `did-witness.json` の本文。`entries` は `[対象の versionId, その版の proof 群]`。 */
const fileOf = (entries: [string, WebVhProof[]][]) =>
  JSON.stringify(entries.map(([versionId, proof]) => ({ versionId, proof })));

async function expectResolves(
  did: string,
  log: WebVhLogEntry[],
  file: string | undefined,
  options?: object,
) {
  return resolveWithWitnessFile(did, log, file, options).result;
}

async function expectRejected(did: string, log: WebVhLogEntry[], file: string | undefined) {
  await expect(resolveWithWitnessFile(did, log, file).result).rejects.toThrow(INVALID_DID);
}

describe('閾値', () => {
  it('2-of-3 の witness のうち 2 つが承認していれば解決でき、メタデータの threshold は文字列', async () => {
    const [w1, w2, w3] = [witnessKey(), witnessKey(), witnessKey()] as [Witness, Witness, Witness];
    const { did, genesis } = witnessedGenesis(2, [w1, w2, w3]);
    const proofs = await Promise.all([w1, w3].map((w) => witnessProofFor(genesis.versionId, w)));
    const { metadata } = await expectResolves(
      did,
      [genesis],
      fileOf([[genesis.versionId, proofs]]),
    );
    expect(metadata.witness).toEqual({
      threshold: '2',
      witnesses: [w1, w2, w3].map((w) => ({ id: w.id })),
    });
  });

  it('閾値に満たない承認（1 件）は拒否される', async () => {
    const [w1, w2] = [witnessKey(), witnessKey()] as [Witness, Witness];
    const { did, genesis } = witnessedGenesis(2, [w1, w2]);
    const proofs = [await witnessProofFor(genesis.versionId, w1)];
    await expectRejected(did, [genesis], fileOf([[genesis.versionId, proofs]]));
  });

  it('同じ witness の proof を重複して並べても 1 票として数える', async () => {
    const [w1, w2] = [witnessKey(), witnessKey()] as [Witness, Witness];
    const { did, genesis } = witnessedGenesis(2, [w1, w2]);
    const proof = await witnessProofFor(genesis.versionId, w1);
    await expectRejected(
      did,
      [genesis],
      fileOf([[genesis.versionId, [proof, proof, { ...proof }]]]),
    );
  });

  it('witness 一覧にない鍵の proof は捨てられ、閾値に数えない', async () => {
    const [w1, w2] = [witnessKey(), witnessKey()] as [Witness, Witness];
    const stranger = witnessKey();
    const { did, genesis } = witnessedGenesis(2, [w1, w2]);
    const proofs = await Promise.all(
      [w1, stranger].map((w) => witnessProofFor(genesis.versionId, w)),
    );
    await expectRejected(did, [genesis], fileOf([[genesis.versionId, proofs]]));
  });

  it('壊れた proof が混じっていても、閾値を満たす有効な proof があれば解決できる（仕様の MAY）', async () => {
    const [w1, w2] = [witnessKey(), witnessKey()] as [Witness, Witness];
    const { did, genesis } = witnessedGenesis(1, [w1, w2]);
    const good = await witnessProofFor(genesis.versionId, w1);
    const broken = { ...(await witnessProofFor(genesis.versionId, w2)), proofValue: 'z3XYZ' };
    await expectResolves(did, [genesis], fileOf([[genesis.versionId, [broken, good]]]));
  });
});

describe('did-witness.json の取得', () => {
  it('witness を使う DID は、隣の did-witness.json を取得する', async () => {
    const w1 = witnessKey();
    const { did, genesis } = witnessedGenesis(1, [w1]);
    const file = fileOf([[genesis.versionId, [await witnessProofFor(genesis.versionId, w1)]]]);
    const { requested, result } = resolveWithWitnessFile(did, [genesis], file);
    await result;
    expect(requested).toEqual([
      'https://vericerts.io/.well-known/did.jsonl',
      'https://vericerts.io/.well-known/did-witness.json',
    ]);
  });

  it('witness を使わない DID は did-witness.json を取得しない', async () => {
    const { did, genesis } = signedGenesis();
    const { requested, result } = resolveWithWitnessFile(did, [genesis], undefined);
    await result;
    expect(requested).toEqual(['https://vericerts.io/.well-known/did.jsonl']);
  });

  it('did-witness.json が無い（404）と解決は失敗する（取得失敗 2003。witness なしとは見なさない）', async () => {
    const w1 = witnessKey();
    const { did, genesis } = witnessedGenesis(1, [w1]);
    await expect(resolveWithWitnessFile(did, [genesis], undefined).result).rejects.toMatchObject({
      code: '2003',
    });
  });

  it.each([
    '',
    'not json',
    '{}',
    '[1]',
    '[{"proof":[]}]',
    '[{"versionId":"1-x","proof":"x"}]',
    '[{"versionId":"1-x","proof":[1]}]',
  ])('構造が壊れた did-witness.json（%p）は拒否される', async (text) => {
    const w1 = witnessKey();
    const { did, genesis } = witnessedGenesis(1, [w1]);
    await expectRejected(did, [genesis], text);
  });

  it('空の配列の did-witness.json は、承認がないので拒否される', async () => {
    const w1 = witnessKey();
    const { did, genesis } = witnessedGenesis(1, [w1]);
    await expectRejected(did, [genesis], '[]');
  });
});

describe('proof の取り扱い', () => {
  it('他の版の versionId への署名は、その版の承認として使えない（versionId のラベルを偽っても署名が合わない）', async () => {
    const w1 = witnessKey();
    const { key, did, genesis } = witnessedGenesis(1, [w1]);
    const v2 = appendSigned([genesis], key);
    const proofForV1 = await witnessProofFor(genesis.versionId, w1);
    // 2 版目の項目に、1 版目への署名を載せる。
    await expectRejected(did, [genesis, v2], fileOf([[v2.versionId, [proofForV1]]]));
  });

  it('Log にない versionId（未公開の版）の項目は捨てられ、他の版の承認として扱われない', async () => {
    const w1 = witnessKey();
    const { did, genesis } = witnessedGenesis(1, [w1]);
    const unpublished = `2-Qm${'U'.repeat(44)}`;
    const proof = await witnessProofFor(unpublished, w1);
    await expectRejected(did, [genesis], fileOf([[unpublished, [proof]]]));
  });

  it('後の版への proof は、それ以前の版の承認も含意する（剪定された did-witness.json）', async () => {
    const w1 = witnessKey();
    const { key, did, genesis } = witnessedGenesis(1, [w1]);
    const v2 = appendSigned([genesis], key);
    const v3 = appendSigned([genesis, v2], key);
    const latestOnly = fileOf([[v3.versionId, [await witnessProofFor(v3.versionId, w1)]]]);
    await expectResolves(did, [genesis, v2, v3], latestOnly);
    // 過去の版を指定して解決しても、検証は Log 全体に対して行われる。
    await expectResolves(did, [genesis, v2, v3], latestOnly, { versionNumber: 1 });
  });

  it('承認が途中の版で止まっていて、最新版が未承認なら拒否される（replay・巻き戻し）', async () => {
    const w1 = witnessKey();
    const { key, did, genesis } = witnessedGenesis(1, [w1]);
    const v2 = appendSigned([genesis], key);
    const stale = fileOf([[genesis.versionId, [await witnessProofFor(genesis.versionId, w1)]]]);
    await expectRejected(did, [genesis, v2], stale);
  });

  it.each([
    ['cryptosuite が違う', { cryptosuite: 'ecdsa-jcs-2019' }],
    ['proofPurpose が違う', { proofPurpose: 'authentication' }],
    ['type が違う', { type: 'Ed25519Signature2020' }],
    ['verificationMethod が did:key でない', { verificationMethod: 'did:web:example.com#key-1' }],
  ])('%s proof は捨てられる', async (_label, patch) => {
    const w1 = witnessKey();
    const { did, genesis } = witnessedGenesis(1, [w1]);
    const proof = { ...(await witnessProofFor(genesis.versionId, w1)), ...patch };
    await expectRejected(did, [genesis], fileOf([[genesis.versionId, [proof]]]));
  });

  it('did:key の本体とフラグメントが食い違う verificationMethod の proof は捨てられる', async () => {
    const [w1, other] = [witnessKey(), witnessKey()] as [Witness, Witness];
    const { did, genesis } = witnessedGenesis(1, [w1]);
    const proof = await witnessProofFor(genesis.versionId, w1);
    const mismatched = { ...proof, verificationMethod: `${w1.id}#${other.key.multikey}` };
    await expectRejected(did, [genesis], fileOf([[genesis.versionId, [mismatched]]]));
  });
});

describe('witness 構成の変更の有効化の時点', () => {
  it('witness を変える版は、変更前の構成で承認され、新しい構成は次の版から有効になる', async () => {
    const [w1, w2] = [witnessKey(), witnessKey()] as [Witness, Witness];
    const { key, did, genesis } = witnessedGenesis(1, [w1]);
    const v2 = appendSigned([genesis], key, {
      witness: { threshold: 1, witnesses: [{ id: w2.id }] },
    });
    const v3 = appendSigned([genesis, v2], key);
    const p1 = await witnessProofFor(genesis.versionId, w1);
    const p2 = await witnessProofFor(v2.versionId, w1);
    // v2 は旧構成（w1）の承認が要り、v3 は新構成（w2）の承認が要る。
    const p3 = await witnessProofFor(v3.versionId, w2);
    await expectResolves(
      did,
      [genesis, v2, v3],
      fileOf([
        [genesis.versionId, [p1]],
        [v2.versionId, [p2]],
        [v3.versionId, [p3]],
      ]),
    );
    // v2 を新構成の witness（w2）が承認しても、旧構成の承認の代わりにならない。
    const wrong = await witnessProofFor(v2.versionId, w2);
    await expectRejected(
      did,
      [genesis, v2, v3],
      fileOf([
        [genesis.versionId, [p1]],
        [v2.versionId, [wrong]],
        [v3.versionId, [p3]],
      ]),
    );
    // v3 を旧構成の witness（w1）だけが承認しても足りない。
    const stale = await witnessProofFor(v3.versionId, w1);
    await expectRejected(
      did,
      [genesis, v2, v3],
      fileOf([
        [genesis.versionId, [p1]],
        [v2.versionId, [p2]],
        [v3.versionId, [stale]],
      ]),
    );
  });

  it('witness を持たない DID が途中で witness を設定すると、その版が即座に承認の対象になる', async () => {
    const w1 = witnessKey();
    const { key, did, genesis } = signedGenesis();
    const v2 = appendSigned([genesis], key, {
      witness: { threshold: 1, witnesses: [{ id: w1.id }] },
    });
    await expectRejected(did, [genesis, v2], fileOf([]));
    const p2 = await witnessProofFor(v2.versionId, w1);
    await expectResolves(did, [genesis, v2], fileOf([[v2.versionId, [p2]]]));
  });

  it('witness を `{}` に戻す版は旧構成の witness が承認する。その後の版は承認を要さない', async () => {
    const w1 = witnessKey();
    const { key, did, genesis } = witnessedGenesis(1, [w1]);
    const v2 = appendSigned([genesis], key, { witness: {} });
    const v3 = appendSigned([genesis, v2], key);
    const p2 = await witnessProofFor(v2.versionId, w1);
    await expectRejected(did, [genesis, v2, v3], fileOf([]));
    // 承認は v2 まで（v3 は承認不要）。proof は v1 も含意する。
    const { metadata } = await expectResolves(
      did,
      [genesis, v2, v3],
      fileOf([[v2.versionId, [p2]]]),
    );
    expect(metadata.witness).toEqual({});
  });
});

describe('署名済みの state 以外は検証済みの鍵で署名されている（witness の検証順）', () => {
  it('witness が承認していても、entryHash が壊れたログは witness の検証に進まず拒否される', async () => {
    const w1 = witnessKey();
    const { key, did, genesis } = witnessedGenesis(1, [w1]);
    const v2 = appendSigned([genesis], key);
    const broken = signEntry({ ...v2, versionId: `2-Qm${'W'.repeat(44)}` }, key);
    const file = fileOf([[broken.versionId, [await witnessProofFor(broken.versionId, w1)]]]);
    const { requested, result } = resolveWithWitnessFile(did, [genesis, broken], file);
    await expect(result).rejects.toThrow(INVALID_DID);
    expect(requested).toEqual(['https://vericerts.io/.well-known/did.jsonl']);
  });
});
