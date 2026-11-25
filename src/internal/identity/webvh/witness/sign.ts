/**
 * witness proof の生成と収集、`did-witness.json` の生成・更新。
 *
 * spec: DIF didwebvh v1.0「Witnessing a DID Version Update」「The Witness Proofs File」、Update (Rotate) 10。
 * 仕様は「ログのエントリを witness に渡す方法」「witness の proof をコントローラに返す方法」を実装に委ねている。SDK は
 * 他の署名 API と同じく、**呼び出し側が渡すコールバック**でこの 2 つを担う（SDK は秘密鍵もネットワーク送信も持たない）。
 *
 * - コントローラ側: {@link collectWebVhWitnessProofs} — 署名済みの候補エントリを各 witness の `approve` コールバックに渡し、
 *   返った proof を検証して、閾値に達したら更新後の `did-witness.json` を返す。
 * - witness 側: {@link createWebVhWitnessProof}（自分の署名コールバックで `versionId` へ proof を作る）と
 *   {@link assertWebVhCandidateVerifies}（候補エントリが、自分が持つ公開済み Log の次のエントリとして全手順で検証できること）。
 *
 * **公開順序（仕様の MUST）**: 更新した `did-witness.json` を**先に**公開し、その後に新しい版を含む `did.jsonl` を公開する。
 *
 * 例外メッセージ・`context` に witness の識別子・鍵・Log 本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { multibaseBase58Encode } from '../../multibase.js';
import type { WebVhLogEntry, WebVhProof } from '../codec.js';
import { assertWitnessFileWithinLimits } from '../lifecycle/append-limits.js';
import { activeParametersOf } from '../parameters.js';
import { eddsaJcs2022HashData } from '../proof.js';
import { verifyChain } from '../verify.js';
import { multikeyOfDidKey } from './config.js';
import type { WebVhWitnessFileItem } from './file.js';
import { verifyWitnessProof, witnessDocumentHash } from './verify.js';

/** 署名コールバック: 署名対象（`eddsa-jcs-2022` の `hashData`、64 バイト）を受け取り、Ed25519 署名（64 バイト）を返す。 */
export type WebVhSignFn = (hashData: Uint8Array) => Promise<Uint8Array> | Uint8Array;

/** witness へ渡す承認依頼。 */
export interface WebVhWitnessRequest {
  /** 承認を求める候補エントリ（コントローラの proof を含む。公開前）。 */
  readonly entry: WebVhLogEntry;
  /** この候補より前の、公開済みの Log。 */
  readonly previousLog: readonly WebVhLogEntry[];
}

/**
 * 承認者（witness）の窓口。`approve` は候補エントリを witness へ届けて proof を受け取るコールバックで、拒否・応答なしは
 * `undefined`（または例外）を返す。届け方（HTTP・メッセージング等）は呼び出し側が決める。
 */
export interface WebVhWitnessApprover {
  /** witness の識別子（`did:key:z6Mk...`）。`witness` パラメータの `witnesses[].id` と同じ値。 */
  readonly id: string;
  readonly approve: (request: WebVhWitnessRequest) => Promise<WebVhProof | undefined>;
}

/** {@link collectWebVhWitnessProofs} の入力。 */
export interface WebVhCollectWitnessProofsOptions {
  /** 承認を求める、署名済みの候補エントリ。 */
  readonly entry: WebVhLogEntry;
  /** 候補より前の、公開済みの Log 全件（初版を含む）。初版の候補では空配列。 */
  readonly previousLog: readonly WebVhLogEntry[];
  /** witness の窓口。承認を要する witness（有効な `witness` パラメータの `witnesses`）のうちの一部か全部。 */
  readonly approvers: readonly WebVhWitnessApprover[];
  /** 現在公開している `did-witness.json` の項目（初版では省略）。 */
  readonly previousWitnessFile?: readonly WebVhWitnessFileItem[];
}

/** witness proof を作る（witness 側）。 */
export interface WebVhWitnessProofSigner {
  /** witness の識別子（`did:key:z6Mk...`、Ed25519）。 */
  readonly id: string;
  readonly sign: WebVhSignFn;
}

function invalid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * `versionId` に対する witness proof を作る（witness 側）。署名対象は `{ "versionId": <versionId> }` で、witness が
 * 自分の判断（候補の検証・承認）を済ませた後にだけ呼ぶ。
 *
 * @param versionId 承認する版の `versionId`。
 * @param signer witness の識別子（`did:key`）と署名コールバック。
 * @returns Data Integrity proof（`eddsa-jcs-2022`・`proofPurpose: assertionMethod`）。
 * @throws `id` が Ed25519 の `did:key` でない・署名が 64 バイトでない場合（VericertsError、code `2001`）。
 */
export async function createWebVhWitnessProof(
  versionId: string,
  signer: WebVhWitnessProofSigner,
): Promise<WebVhProof> {
  const multikey = multikeyOfDidKey(signer.id);
  const proofConfig = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: `did:key:${multikey}#${multikey}`,
    created: new Date().toISOString(),
    proofPurpose: 'assertionMethod',
  };
  const signature = await signer.sign(
    eddsaJcs2022HashData(proofConfig, witnessDocumentHash(versionId)),
  );
  if (signature.length !== 64) {
    throw invalid();
  }
  return { ...proofConfig, proofValue: multibaseBase58Encode(signature) };
}

/**
 * 候補エントリが、公開済みの Log の次のエントリとして全手順（Read (Resolve)）で検証できることを確かめる（witness 側の
 * 承認前の検証。仕様: 各 witness は候補を独立に検証し、失敗したら承認を拒否する MUST）。
 *
 * @param previousLog witness が持つ公開済みの Log（空なら初版の候補）。
 * @param candidate 承認を求められた候補エントリ。
 * @throws 検証に失敗する場合（VericertsError、code `2001`）。
 */
export function assertWebVhCandidateVerifies(
  previousLog: readonly WebVhLogEntry[],
  candidate: WebVhLogEntry,
): void {
  const did = ownProperty<{ id?: unknown }>(candidate, 'state')?.id;
  const scid = ownProperty<{ scid?: unknown }>(previousLog[0] ?? candidate, 'parameters')?.scid;
  if (typeof did !== 'string' || typeof scid !== 'string') {
    throw invalid();
  }
  verifyChain([...previousLog, candidate], did, scid);
}

/**
 * 候補エントリの witness proof を収集し、更新後の `did-witness.json` の項目を返す（コントローラ側）。
 *
 * 承認を要する witness は、候補の版が要する構成（初版・`{}` から設定する版は自身の `witness`、それ以外は前版までに有効な
 * `witness`）で決まる。`approvers` のうちその構成に含まれる witness の `approve` を呼び、返った proof を検証し
 * （不正・別の witness を名乗る・重複した proof は捨てる）、閾値に達したら返す。承認が閾値に満たなければ拒否する。
 *
 * 返す項目は、既存の項目のうち候補より後ろの版（未公開）を除き、各 witness の最新の proof だけを残して剪定したもの
 * （仕様: コントローラは公開済みの版について witness ごとに最新の proof だけ残す SHOULD）。proof の無い項目は含めない。
 *
 * @param options 候補エントリ・公開済みの Log・witness の窓口・現在の witness proof ファイル。
 * @returns 更新後の `did-witness.json` の項目（JSON にして公開する。**`did.jsonl` より先に公開する**）。
 * @throws 候補の版が witness を要さない・承認が閾値に満たない・窓口の `id` が重複する／承認を要する witness でない場合
 *   （VericertsError、code `2001`）。
 */
export async function collectWebVhWitnessProofs(
  options: WebVhCollectWitnessProofsOptions,
): Promise<WebVhWitnessFileItem[]> {
  const entry = ownProperty<WebVhLogEntry>(options, 'entry') as WebVhLogEntry;
  const previousLog = ownProperty<readonly WebVhLogEntry[]>(options, 'previousLog') ?? [];
  const approvers = ownProperty<readonly WebVhWitnessApprover[]>(options, 'approvers') ?? [];
  const previousFile =
    ownProperty<readonly WebVhWitnessFileItem[]>(options, 'previousWitnessFile') ?? [];
  const parametersOf = (entries: readonly WebVhLogEntry[]) => activeParametersOf(entries);
  const before = previousLog.length === 0 ? undefined : parametersOf(previousLog);
  const after = parametersOf([...previousLog, entry]);
  const required = before === undefined ? after.witness : (before.witness ?? after.witness);
  if (required === undefined) {
    throw invalid();
  }
  const allowed = new Set(required.witnesses);
  if (
    new Set(approvers.map((approver) => approver.id)).size !== approvers.length ||
    approvers.some((approver) => !allowed.has(approver.id))
  ) {
    throw invalid();
  }
  const budget = { remaining: required.witnesses.length };
  const accepted = new Map<string, WebVhProof>();
  for (const approver of approvers) {
    let proof: WebVhProof | undefined;
    try {
      proof = await approver.approve({ entry, previousLog });
    } catch {
      continue;
    }
    if (proof === undefined) {
      continue;
    }
    // 返ってきた proof は信用せず、その witness の proof として検証する（別の witness の鍵・別の版の署名は捨てる）。
    const id = verifyWitnessProof(proof, entry.versionId, new Set([approver.id]), budget);
    if (id !== undefined) {
      accepted.set(id, proof);
    }
  }
  if (accepted.size < required.threshold) {
    throw invalid();
  }
  return pruneWitnessFile(previousLog, previousFile, {
    versionId: entry.versionId,
    proof: [...accepted.values()],
  });
}

/**
 * 既存の項目に新しい項目を加え、剪定する: 未公開の版（Log にない `versionId`）の項目を捨て、各 witness の最新の proof
 * だけを残す。新しい項目の witness は、その witness の古い proof を置き換える。
 */
function pruneWitnessFile(
  previousLog: readonly WebVhLogEntry[],
  previousFile: readonly WebVhWitnessFileItem[],
  added: WebVhWitnessFileItem,
): WebVhWitnessFileItem[] {
  const order = new Map(previousLog.map((entry, index) => [entry.versionId, index]));
  order.set(added.versionId, previousLog.length);
  const published = previousFile
    .filter((item) => order.has(item.versionId))
    .sort((a, b) => (order.get(b.versionId) as number) - (order.get(a.versionId) as number));
  const seen = new Set<string>();
  const result: WebVhWitnessFileItem[] = [];
  for (const item of [added, ...published]) {
    const proof = item.proof.filter((p) => {
      const method = ownProperty<unknown>(p, 'verificationMethod');
      const id = typeof method === 'string' ? method : '';
      if (seen.has(id)) {
        return false;
      }
      seen.add(id);
      return true;
    });
    if (proof.length > 0) {
      result.push({ versionId: item.versionId, proof });
    }
  }
  const file = result.reverse();
  assertWitnessFileWithinLimits(file);
  return file;
}
