/**
 * 個別 / フィルタ削除（Art.17）の署名検証済み構造的証跡の解決。
 *
 * `chain.ts` の `verifyDashboardLogChain` が「削除記録と矛盾なく説明できる欠損は `sequenceGap` に
 * しない」判定に使う入力（{@link DashboardLogDeletionRecords}）を組み立てる責務を切り出す
 * （`entry-signature.ts` が署名検証を、本モジュールが `deletion-log/` の読み取り後の解決を、
 * `chain.ts` が chain 上の適用を、それぞれ担う 3 分割）。
 */

import type { DashboardLogEntry, DeletedLogEntryRecord } from '../types.js';
import {
  type DashboardLogVerifierKey,
  type DashboardLogVerifierKeyResolver,
  extractKid,
  verifyEntrySignature,
} from './entry-signature.js';
import { snapshotDashboardLogEntry } from './entry-snapshot.js';

/**
 * 個別 / フィルタ削除（Art.17）の構造的証跡を連番で引けるようにした形。
 *
 * `DashboardLog.deleteLogEntry` / `deleteLogEntries` が `deletion-log/` パーティションへ JWS 署名付きで
 * 残す {@link ../types.js!LogEntryDeletedPayload} の `deletions` を、署名検証済みのものだけ集めて
 * `seq` をキーに束ねたもの（{@link resolveDeletionRecords}）。`verifyDashboardLogChain` はこれを使って
 * 「削除記録と矛盾なく説明できる欠損」を `sequenceGap` から除外する。
 */
export type DashboardLogDeletionRecords = ReadonlyMap<number, DeletedLogEntryRecord>;

/**
 * `deletion-log/` パーティションの `logEntryDeleted` エントリから、署名検証に通ったものだけを
 * `seq → 証跡` の形へ束ねる。
 *
 * **署名を検証できない削除記録は無視する（fail-safe）。** `deletion-log/` パーティション自体は
 * chain 検証の対象ではないため（本関数は連番の連続性を見ない）、記録の真正性はエントリ単位の JWS
 * 署名だけが担保する。K4 暗号化ブロブの書込鍵（AEAD）を持つがペルソナ / Dashboard ログ専用鍵を
 * 持たない攻撃者が偽の削除記録を紛れ込ませても、署名検証に落ちて無視されるため、対応する
 * `dashboard-log/` 側の欠損は引き続き `sequenceGap` として報告される。
 *
 * @param deletionLogEntries `deletion-log/` パーティションから読み出したエントリ（復号済み。追記順は
 *   問わない）。
 * @param verifierKeyOrResolver `dashboard-log/` の検証と同じ検証鍵 / `kid` リゾルバ。
 * @returns 検証済みの削除証跡を `seq` で引けるマップ（{@link DashboardLogDeletionRecords}）。
 */
export function resolveDeletionRecords(
  deletionLogEntries: readonly DashboardLogEntry[],
  verifierKeyOrResolver: DashboardLogVerifierKey | DashboardLogVerifierKeyResolver,
): DashboardLogDeletionRecords {
  const records = new Map<number, DeletedLogEntryRecord>();
  // 公開 API の入力は own の写しへ畳んでから読む（`chain.ts` と同じ理由）。
  for (const entry of deletionLogEntries.map(snapshotDashboardLogEntry)) {
    if (entry.type !== 'logEntryDeleted') {
      continue;
    }
    const verifierKey =
      typeof verifierKeyOrResolver === 'function'
        ? verifierKeyOrResolver(extractKid(entry))
        : verifierKeyOrResolver;
    if (verifierKey === undefined || !verifyEntrySignature(entry, verifierKey)) {
      continue;
    }
    for (const record of extractDeletedLogEntryRecords(entry.payload)) {
      records.set(record.seq, record);
    }
  }
  return records;
}

/** `logEntryDeleted` payload の `deletions` を実行時に検証しながら取り出す（storage 破損への防御）。 */
function extractDeletedLogEntryRecords(
  payload: Readonly<Record<string, unknown>>,
): readonly DeletedLogEntryRecord[] {
  const { deletions } = payload;
  if (!Array.isArray(deletions)) {
    return [];
  }
  const result: DeletedLogEntryRecord[] = [];
  for (const item of deletions) {
    if (typeof item !== 'object' || item === null) {
      continue;
    }
    const { seq, prevHash, entryHash } = item as Record<string, unknown>;
    if (
      typeof seq === 'number' &&
      Number.isInteger(seq) &&
      seq >= 0 &&
      (prevHash === null || typeof prevHash === 'string') &&
      typeof entryHash === 'string'
    ) {
      result.push({ seq, prevHash, entryHash });
    }
  }
  return result;
}

/**
 * `startSeq`（含む）から `endSeqExclusive`（含まない）までの連番すべてが削除記録で連続に説明できるかを
 * 判定する。
 *
 * 削除記録は「削除したエントリが持っていた `prevHash`」と「削除したエントリ自身のハッシュ
 * （`entryHash`。次エントリの `prevHash` に相当）」を持つため、`priorHash`（欠損区間の直前に残る
 * `prevHash` 相当値）から 1 件ずつたどれる。途中で記録が無い、または `prevHash` が食い違えば
 * `undefined`（= 説明できない。通常の `sequenceGap` 判定にフォールバックする）を返す。
 *
 * @param priorHash 欠損区間の直前エントリの signing-input ハッシュ。区間が chain の起点（連番 0）を
 *   含む場合は `null`。
 * @returns 説明できた場合、欠損区間の直後エントリが持つべき `prevHash`。説明できなければ `undefined`。
 */
export function resolveDeletionSpan(
  startSeq: number,
  endSeqExclusive: number,
  priorHash: string | null,
  deletionRecords: DashboardLogDeletionRecords,
): string | null | undefined {
  let expected: string | null = priorHash;
  for (let seq = startSeq; seq < endSeqExclusive; seq += 1) {
    const record = deletionRecords.get(seq);
    if (record === undefined || record.prevHash !== expected) {
      return undefined;
    }
    expected = record.entryHash;
  }
  return expected;
}
