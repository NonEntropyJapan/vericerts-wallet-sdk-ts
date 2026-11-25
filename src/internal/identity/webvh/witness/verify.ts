/**
 * witness proof の検証。DIF didwebvh v1.0「Verifying Witness Proofs During Resolution」と
 * 「Witness Threshold Algorithm」に対応する。
 *
 * 前提: Log の非 witness 検証（entryHash・署名・parameters。`../verify.ts`）を**先に**終えている（witness 検証は
 * それらの代わりにならない）。
 *
 * - 承認を要する版: 初版は自身の `witness`、以降は前版までに有効な `witness`（`{}` から設定する版は、その版自身が即座に対象）。
 *   `witness` を変える版が有効になるのは公開**後**（次の版から）。
 * - `did-witness.json` の項目のうち、`versionId` がこの Log にある版のものだけを使う（無いもの・将来の版は捨てる）。
 * - proof は `eddsa-jcs-2022`（`type: DataIntegrityProof`・`proofPurpose: assertionMethod`）で、署名対象は
 *   `{ "versionId": <versionId> }`。`verificationMethod` は `did:key:<multibase>#<multibase>`（本体とフラグメントが一致）で、
 *   公開鍵はその本体だけから決める（DID 解決・他の鍵ストアは使わない）。
 * - proof は有効な witness 一覧のどれかに帰属し、witness の `id` ごとに最大 1 票。帰属できない proof・検証に失敗した proof は
 *   捨てる（閾値の計数に入れない）。
 * - 版 i の承認 = 有効な witness のうち閾値以上が、版 i **以降**のいずれかの公開済みの版に有効な proof を持つ
 *   （proof は「それ以前の全ての版」の承認を含意する）。満たせなければ解決を中断する。
 *
 * 検証量は縛る: witness ごとに「新しい版の proof から順に、最初に有効なものまで」しか検証せず、検証回数はログ 1 本あたり
 * `MAX_WITNESS_SIGNATURES_PER_LOG`、スコープ全体の予算にも計上する。
 *
 * 例外メッセージ・`context` に witness の識別子・鍵を含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { ResolutionWorkBudget } from '../../resolution-budget.js';
import type { WebVhProof } from '../codec.js';
import {
  consumeSignatureBudget,
  createWitnessSignatureBudget,
  MAX_WITNESS_PROOFS_PER_ITEM,
  rejectDidLogOversized,
  type SignatureBudget,
} from '../limits.js';
import { documentHashOf, multikeyFromVerificationMethod, verifyProofSignature } from '../proof.js';
import type { VerifiedLog } from '../verify.js';
import { multikeyOfDidKey } from './config.js';
import type { WebVhWitnessFileItem } from './file.js';

const PROOF_TYPE = 'DataIntegrityProof';
const PROOF_CRYPTOSUITE = 'eddsa-jcs-2022';
const PROOF_PURPOSE = 'assertionMethod';

/** witness proof の署名対象（`{ versionId }` の JCS ハッシュ）。 */
export function witnessDocumentHash(versionId: string): Uint8Array {
  return documentHashOf({ versionId });
}

/**
 * proof の形（type / cryptosuite / proofPurpose / verificationMethod の did:key 規則）を確かめ、witness の識別子
 * （`did:key:<multikey>`）を返す。署名は検証しない。条件を満たさなければ `undefined`（捨てる proof）。
 */
export function witnessIdOfProof(proof: WebVhProof): string | undefined {
  const verificationMethod = ownProperty<unknown>(proof, 'verificationMethod');
  if (
    ownProperty<unknown>(proof, 'type') !== PROOF_TYPE ||
    ownProperty<unknown>(proof, 'cryptosuite') !== PROOF_CRYPTOSUITE ||
    ownProperty<unknown>(proof, 'proofPurpose') !== PROOF_PURPOSE ||
    typeof verificationMethod !== 'string' ||
    typeof ownProperty<unknown>(proof, 'proofValue') !== 'string'
  ) {
    return undefined;
  }
  try {
    return `did:key:${multikeyFromVerificationMethod(verificationMethod)}`;
  } catch {
    return undefined;
  }
}

/**
 * `versionId` に対する witness の proof を検証する（形・帰属先の witness・署名）。
 *
 * @returns 有効なら proof を出した witness の識別子、そうでなければ `undefined`（捨てる proof）。
 */
export function verifyWitnessProof(
  proof: WebVhProof,
  versionId: string,
  allowedIds: ReadonlySet<string>,
  budget: SignatureBudget,
): string | undefined {
  const id = witnessIdOfProof(proof);
  if (id === undefined || !allowedIds.has(id)) {
    return undefined;
  }
  consumeSignatureBudget(budget);
  return verifyProofSignature(proof, witnessDocumentHash(versionId), multikeyOfDidKey(id))
    ? id
    : undefined;
}

/**
 * Log の全版について、承認を要する版が閾値以上の witness に承認されていることを検証する。
 *
 * @param log 検証済みの Log（`verifyChain` の結果）。
 * @param items `did-witness.json` の項目。
 * @param scope 解決スコープ全体の仕事量予算（署名検証を計上する）。
 * @throws 承認が閾値に満たない・proof 数が上限を超える場合（VericertsError、code `2001`）。
 */
export function verifyWitnessApprovals(
  log: VerifiedLog,
  items: readonly WebVhWitnessFileItem[],
  scope?: ResolutionWorkBudget,
): void {
  const indexOfVersion = new Map(log.entries.map((entry, index) => [entry.versionId, index]));
  // 版の添字ごとの proof 群（Log にない `versionId` の項目は捨てる）。
  const proofsByIndex = new Map<number, readonly WebVhProof[]>();
  for (const item of items) {
    const index = indexOfVersion.get(item.versionId);
    if (index !== undefined) {
      proofsByIndex.set(index, [...(proofsByIndex.get(index) ?? []), ...item.proof]);
      rejectDidLogOversized(proofsByIndex.get(index)?.length ?? 0, MAX_WITNESS_PROOFS_PER_ITEM);
    }
  }
  const budget = createWitnessSignatureBudget(scope);
  // witness `id` → その witness が有効な proof を出した最も新しい版の添字。
  const latestApproved = new Map<string, number>();
  const candidates = new Set(
    log.witnessRequired.flatMap((config) => (config === undefined ? [] : config.witnesses)),
  );
  const indexes = [...proofsByIndex.keys()].sort((a, b) => b - a);
  for (const index of indexes) {
    const versionId = (log.entries[index] as VerifiedLog['entries'][number]).versionId;
    for (const proof of proofsByIndex.get(index) ?? []) {
      const id = witnessIdOfProof(proof);
      // 既により新しい版で承認済みの witness の、古い版の proof は検証しない。
      if (id === undefined || !candidates.has(id) || latestApproved.has(id)) {
        continue;
      }
      if (verifyWitnessProof(proof, versionId, candidates, budget) !== undefined) {
        latestApproved.set(id, index);
      }
    }
  }
  for (const [index, config] of log.witnessRequired.entries()) {
    if (config === undefined) {
      continue;
    }
    const approvals = config.witnesses.filter((id) => (latestApproved.get(id) ?? -1) >= index);
    if (approvals.length < config.threshold) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
  }
}
