/**
 * `did-witness.json`（witness proof ファイル）のパース。
 *
 * spec: DIF didwebvh v1.0「The Witness Proofs File」。データモデルは
 * `[ { "versionId": "<n>-<entryHash>", "proof": [ <Data Integrity proof>, ... ] }, ... ]`。
 *
 * 取得先は攻撃者が選べるので、署名検証より前に件数・サイズだけで拒否する:
 * 配列の項目数・1 項目あたりの proof 数・ファイル全体の proof 数は `limits.ts` の上限で縛る。
 * 個々の proof の中身（署名・鍵）は検証しない（`./verify.ts`）。構造が崩れたファイルは拒否し、「witness なし」には読み替えない。
 *
 * 例外メッセージ・`context` に Log 本文・鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../../prototype-safety/parse-json.js';
import type { WebVhProof } from '../codec.js';
import {
  MAX_WITNESS_FILE_ITEMS,
  MAX_WITNESS_FILE_PROOFS,
  MAX_WITNESS_PROOFS_PER_ITEM,
  rejectDidLogOversized,
} from '../limits.js';

/** `did-witness.json` の 1 項目: ある版の `versionId` と、その版に対する witness の proof 群。 */
export interface WebVhWitnessFileItem {
  readonly versionId: string;
  readonly proof: readonly WebVhProof[];
}

function invalid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * `did-witness.json` のテキストをパースする。
 *
 * @param text ファイル本文（JSON 配列）。
 * @returns 項目配列（`proof` を欠く項目は空配列として扱う。仕様は proof の無い項目を取り除くよう SHOULD するが、あっても無害）。
 * @throws JSON 不正・配列でない・項目が `{ versionId: string, proof?: object[] }` でない・件数が上限を超える場合
 *   （VericertsError、code `2001`。件数超過は `context.reason: 'did_log_too_large'`）。
 */
export function parseWitnessFile(text: string): WebVhWitnessFileItem[] {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(text);
  } catch {
    throw invalid();
  }
  if (!Array.isArray(parsed)) {
    throw invalid();
  }
  rejectDidLogOversized(parsed.length, MAX_WITNESS_FILE_ITEMS);
  let totalProofs = 0;
  const items: WebVhWitnessFileItem[] = [];
  for (const raw of parsed as unknown[]) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw invalid();
    }
    const versionId = ownProperty<unknown>(raw, 'versionId');
    const proof = ownProperty<unknown>(raw, 'proof') ?? [];
    if (typeof versionId !== 'string' || !Array.isArray(proof)) {
      throw invalid();
    }
    rejectDidLogOversized(proof.length, MAX_WITNESS_PROOFS_PER_ITEM);
    totalProofs += proof.length;
    rejectDidLogOversized(totalProofs, MAX_WITNESS_FILE_PROOFS);
    if (proof.some((p) => typeof p !== 'object' || p === null || Array.isArray(p))) {
      throw invalid();
    }
    items.push({ versionId, proof: proof as WebVhProof[] });
  }
  return items;
}
