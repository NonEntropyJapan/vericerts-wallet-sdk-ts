/**
 * 検証済みエクスポートの取り込み先書込（`DashboardLog.importLog` の本体。`dashboard-log.ts` の行数を抑えるため切り出し）。
 * 呼び出し側が `append` と同じロックで包むこと（空判定 → 書込の原子性。連番衝突による上書きを防ぐ）。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { encodeDashboardLogEntry } from '../codec.js';
import { writeTailAnchor } from '../log-integrity/tail-anchor.js';
import type { DashboardLogEntry } from '../types.js';
import { DASHBOARD_LOG_KEY_PREFIX, type DashboardLogStorage } from './dashboard-log-shared.js';

/**
 * 検証済みエントリを署名・`prevHash` ごと verbatim 永続化する（再署名せず chain 連続性を保つ）。
 * 取り込んだ連鎖の末尾を新たな末尾アンカーにする（以前の連鎖のアンカーは置換される）。
 *
 * @returns 取り込んだ件数。
 * @throws 既存の `dashboard-log/` が空でない場合（`GDPR_DASHBOARD_LOG_NOT_EMPTY`、10604）。
 */
export async function persistImportedEntries(
  storage: DashboardLogStorage,
  entries: readonly DashboardLogEntry[],
): Promise<number> {
  if ((await storage.list(DASHBOARD_LOG_KEY_PREFIX)).length > 0) {
    throw new VericertsError(ErrorCodes.GDPR_DASHBOARD_LOG_NOT_EMPTY);
  }
  for (const entry of entries) {
    await storage.set(`${DASHBOARD_LOG_KEY_PREFIX}${entry.id}`, encodeDashboardLogEntry(entry));
  }
  const last = entries[entries.length - 1];
  if (last !== undefined) await writeTailAnchor(storage, DASHBOARD_LOG_KEY_PREFIX, last);
  return entries.length;
}
