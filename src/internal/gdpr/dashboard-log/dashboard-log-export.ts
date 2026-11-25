/**
 * Dashboard ログのエクスポート NDJSON の組み立て（Art.15、Art.20、`DashboardLog.exportLog`）。
 *
 * 各エントリ行（署名済みの正準 payload をそのまま含む）に続けて、末尾に Merkle ルートハッシュ行
 * （`{ merkleRoot, count }`）を置く。0 件時は `merkleRoot: null`。
 *
 * **欠損のあるエクスポートには `partial: true` を付ける。** 絞り込み
 * （`types` / `rpIdentifier` / `olderThan` 等）・Art.17 削除・保持上限による先頭切り捨てを経たログは、
 * 先頭の `prevHash` が `null` でない、または隣り合う行の `prevHash` が直前行のハッシュと一致しない。
 * これを従来の「欠損なし」前提のまま出力すると、自 SDK の `importLog` が必ず `3010` で拒否する出力になる。
 * `partial` は「この出力は元の chain の部分列である」という宣言で、インポート側は先頭 `null` と
 * 全行の隣接性の要求を外し、署名と（連番が隣り合う行どうしの）`prevHash` のみを検証する
 * （`dashboard-log-import.ts`）。欠損の無い出力にはフィールドを付けず、従来の形のまま出す。
 */

import type { DashboardLogEntry } from '../types.js';
import { signingInputHash } from './dashboard-log-shared.js';

/** `entries` が chain の先頭（`prevHash: null`）から欠損なく連結しているか。 */
function isContinuousFromGenesis(entries: readonly DashboardLogEntry[]): boolean {
  return entries.every((entry, i) => {
    const previous = entries[i - 1];
    return previous === undefined
      ? entry.prevHash === null
      : entry.prevHash === signingInputHash(previous);
  });
}

/**
 * 追記順のエントリ列を NDJSON テキストにする（各レコードを改行で区切る。末尾改行は付けない。
 * 行数 = エントリ数 + ルートハッシュ行 1）。
 */
export function buildDashboardLogExport(entries: readonly DashboardLogEntry[]): string {
  const lines = entries.map((entry) => JSON.stringify(entry));
  const last = entries[entries.length - 1];
  const merkleRoot = last === undefined ? null : signingInputHash(last);
  const partial = isContinuousFromGenesis(entries) ? {} : { partial: true };
  lines.push(JSON.stringify({ merkleRoot, count: entries.length, ...partial }));
  return lines.join('\n');
}
