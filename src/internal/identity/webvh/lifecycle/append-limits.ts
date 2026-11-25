/**
 * DID Log 生成・更新（`createDid*` / `updateDid*`）が検証側の上限を超えるログを作らないための検査。
 *
 * 検証側（`parseDidLog` / `verifyChain` / `fetchDidLog`）は版数 `MAX_LOG_ENTRIES`・1 行 `MAX_LOG_ENTRY_CHARS`・
 * ログ全体 `MAX_DOCUMENT_BYTES`・鍵ハッシュ計算 `MAX_KEY_HASHES_PER_LOG` を課す。DID Log はハッシュ鎖の追記専用で
 * 途中を切り詰められないため、生成側がこれらを超えて追記すると、その DID は**以後永久に解決不能**になる
 * （ホスティング側で末尾を削るしか回復手段が無い）。生成側は署名・公開の前に、検証側と**同じ定数**
 * （`limits.ts` / `http/body-limit.ts`）で候補エントリを検査して 2001（`did_log_too_large`）で拒否する。
 *
 * 署名（proof）は呼び出し側が後段で付与するため、候補エントリには proof が無い。検証側の 1 行・ログ全体の上限は
 * proof 付きの長さに対して効くので、proof 1 件ぶんの余白（`PROOF_RESERVE_CHARS`）を見込む。
 */

import { MAX_DOCUMENT_BYTES } from '../../../http/body-limit.js';
import type { WebVhLogEntry } from '../codec.js';
import {
  MAX_KEY_HASHES_PER_LOG,
  MAX_LOG_ENTRIES,
  MAX_LOG_ENTRY_CHARS,
  MAX_WITNESS_FILE_ITEMS,
  MAX_WITNESS_FILE_PROOFS,
  MAX_WITNESS_PROOFS_PER_ITEM,
  rejectDidLogOversized,
} from '../limits.js';
import { readParameterDelta } from '../parameters.js';
import type { WebVhWitnessFileItem } from '../witness/file.js';

/**
 * 呼び出し側が後から付与する proof 1 件ぶん（`,"proof":[{…}]`）の見込み文字数。実際の Data Integrity proof
 * （type / cryptosuite / `did:key:<multikey>#<multikey>` / created / proofPurpose / proofValue）は
 * 約 450 文字なので、倍以上の余白を取る。
 */
export const PROOF_RESERVE_CHARS = 1_024;

/** UTF-8 バイト数（`fetchDidLog` の本文上限はバイト数で効くため）。 */
function utf8Length(text: string): number {
  return new TextEncoder().encode(text).length;
}

/**
 * `entries`（previousLog + 候補）を検証側と同じ規則でたどったときの事前コミット用鍵ハッシュ計算回数を数え、
 * `MAX_KEY_HASHES_PER_LOG` を超えるなら拒否する。数え方は `verifyChain` / `verifyKeyPreCommit` と同じ:
 * 前版までの有効な `nextKeyHashes`（省略した版は繰り越す）が非空の間、2 版目以降が宣言する updateKeys の
 * 件数ぶん計算される。
 */
function assertKeyHashBudget(entries: readonly WebVhLogEntry[]): void {
  let committed: readonly string[] = [];
  let hashes = 0;
  for (const [index, entry] of entries.entries()) {
    const delta = readParameterDelta(entry.parameters, index === 0);
    if (index > 0 && committed.length > 0) {
      hashes += delta.updateKeys?.length ?? 0;
      rejectDidLogOversized(hashes, MAX_KEY_HASHES_PER_LOG);
    }
    committed = delta.nextKeyHashes ?? committed;
  }
}

/**
 * 候補エントリを `previousLog` の末尾に追記してよいかを、検証側の上限で検査する。
 *
 * - 版数: `previousLog.length + 1` が `MAX_LOG_ENTRIES` 以下。
 * - 1 行の長さ: 候補を proof 付きで直列化した長さが `MAX_LOG_ENTRY_CHARS` 以下。
 * - ログ全体: 直列化した全行（改行込み）の UTF-8 バイト数が `MAX_DOCUMENT_BYTES` 以下。
 * - 鍵ハッシュ: 事前コミット検証の計算回数が `MAX_KEY_HASHES_PER_LOG` 以下。
 *
 * 版数を最初に見るので、巨大な `previousLog` を直列化する前に拒否できる。
 *
 * @param previousLog 追記先の既存エントリ（初版の生成では空）。
 * @param candidate proof 前の候補エントリ。
 * @throws いずれかの上限を超える場合（VericertsError、code `2001`、`context.reason: 'did_log_too_large'`）。
 */
export function assertLogAppendWithinLimits(
  previousLog: readonly WebVhLogEntry[],
  candidate: WebVhLogEntry,
): void {
  rejectDidLogOversized(previousLog.length + 1, MAX_LOG_ENTRIES);
  const candidateLine = JSON.stringify(candidate);
  rejectDidLogOversized(candidateLine.length + PROOF_RESERVE_CHARS, MAX_LOG_ENTRY_CHARS);
  // 候補の直列化行 + proof 1 件ぶん + 改行。既存行は proof 込みで直列化済みの実長を数える。
  let totalBytes = utf8Length(candidateLine) + PROOF_RESERVE_CHARS + 1;
  for (const entry of previousLog) {
    totalBytes += utf8Length(JSON.stringify(entry)) + 1;
    rejectDidLogOversized(totalBytes, MAX_DOCUMENT_BYTES);
  }
  rejectDidLogOversized(totalBytes, MAX_DOCUMENT_BYTES);
  assertKeyHashBudget([...previousLog, candidate]);
}

/**
 * 生成する `did-witness.json` が、検証側（`parseWitnessFile` / `fetchDidLog`）の上限を超えないことを検査する。
 * 超えるファイルを公開すると、その DID は witness の検証で解決不能になる。
 *
 * @param items 公開する項目。
 * @throws 項目数・1 項目あたりの proof 数・全体の proof 数・直列化したバイト数が上限を超える場合
 *   （VericertsError、code `2001`、`context.reason: 'did_log_too_large'`）。
 */
export function assertWitnessFileWithinLimits(items: readonly WebVhWitnessFileItem[]): void {
  rejectDidLogOversized(items.length, MAX_WITNESS_FILE_ITEMS);
  let totalProofs = 0;
  for (const item of items) {
    rejectDidLogOversized(item.proof.length, MAX_WITNESS_PROOFS_PER_ITEM);
    totalProofs += item.proof.length;
  }
  rejectDidLogOversized(totalProofs, MAX_WITNESS_FILE_PROOFS);
  rejectDidLogOversized(utf8Length(JSON.stringify(items)), MAX_DOCUMENT_BYTES);
}
