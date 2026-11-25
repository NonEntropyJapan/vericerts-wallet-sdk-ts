/**
 * Dashboard ログのユーザー制御エントリ物理削除（Art.17 忘れられる権利 / 削除権）。
 *
 * `DashboardLog.deleteEntriesForVc`と `DashboardLog.purge`
 * （purgeDashboardLog）の実装を切り出す。いずれも `dashboard-log/`
 * パーティションのみを対象とし、監査用の Art.17 削除記録（`deletion-log/`）は削除しない。chain の
 * 再連結は行わない（ユーザー主導の削除権行使を優先し、残存エントリの `prevHash` は当時の値のまま保持する）。
 * 削除で空いた連番の穴は、削除証跡（`logEntryDeleted`、{@link deleteMatchingWithAuditRecord}）が説明する。
 * `DashboardLog.deleteEntriesForVc` は証跡付きで、本ファイルの {@link deleteEntriesForVc} は証跡を
 * 組み立てられないエントリ（連番として読めない ID）の最終掃除にだけ使う。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { decodeDashboardLogEntry } from '../codec.js';
import { entryMatchesFilter, isUnrestrictedFilter } from '../log-filter.js';
import { seqOf } from '../log-integrity/entry-signature.js';
import type { DashboardLogEntry, DeletedLogEntryRecord, LogFilter } from '../types.js';
import {
  DASHBOARD_LOG_KEY_PREFIX,
  type DashboardLogStorage,
  signingInputHash,
} from './dashboard-log-shared.js';

/**
 * 保存済みバイト列を復号する。復号不能（`STORAGE_RECORD_CORRUPTED` = 6005）なら `undefined`。
 *
 * 削除経路（Art.17）は破損エントリ 1 件で全体を中断してはならない。中断すると破損より後ろの正常な
 * エントリが恒久的に消せず、`deleteCredential` では監査記録だけが毎回積み増される。
 * 破損の検知・報告は `verify`（`undecodable`）の責務であり、ここでは復号失敗のみを畳む
 * （それ以外の例外は握り潰さない）。
 */
function decodeOrUndefined(stored: Uint8Array): DashboardLogEntry | undefined {
  try {
    return decodeDashboardLogEntry(stored);
  } catch (error) {
    if (error instanceof VericertsError && error.code === ErrorCodes.STORAGE_RECORD_CORRUPTED) {
      return undefined;
    }
    throw error;
  }
}

/**
 * エントリ payload が指定 VC を参照するかを判定する。
 *
 * **VC ID の持ち方は種別ごとに違う。** `correctionRequest` は payload 直下の `vcId`、
 * `consentRevoked` は `scope.vcId`、`presentation` は **`credentialIds`（配列）** である
 * （`presentation-log.ts` の `buildPresentationEventPayload` は直下 `vcId` を書かない）。
 * 配列形を見落とすと、「どの RP がいつ何のクレームを見たか」という第三者開示履歴だけが
 * `deleteCredential` 後も残る。Art.17 が消去の対象としているのはまさにその記録なので、3 形すべてを
 * 確認する。
 */
export function payloadReferencesVc(
  payload: Readonly<Record<string, unknown>>,
  vcId: string,
): boolean {
  if (payload.vcId === vcId) {
    return true;
  }
  const credentialIds = payload.credentialIds;
  if (Array.isArray(credentialIds) && credentialIds.includes(vcId)) {
    return true;
  }
  const scope = payload.scope;
  return (
    typeof scope === 'object' && scope !== null && (scope as Record<string, unknown>).vcId === vcId
  );
}

/**
 * 特定 VC を参照するユーザー制御 Dashboard ログエントリ（`dashboard-log/`）を**削除証跡なしで**物理削除する
 * （Art.17 忘れられる権利）。公開の削除経路は証跡付きの `DashboardLog.deleteEntriesForVc`。
 *
 * 当該 VC を参照するエントリを storage から削除する。参照は payload 直下の `vcId`
 * （`correctionRequest`）・`scope.vcId`（`consentRevoked`）・`credentialIds` 配列（`presentation`）の
 * 3 形を対象とする（{@link payloadReferencesVc}）。削除監査記録（`deletion-log/`）は対象外。
 *
 * 復号不能（破損）なエントリは VC を参照するか判定できないため削除せず読み飛ばし、他のエントリの
 * 削除を続行する（破損は `DashboardLog.verify` が `undecodable` として報告する）。
 *
 * @param storage エントリの永続化先。
 * @param vcId 削除対象 VC の ID。
 * @returns 物理削除したエントリ数。
 */
export async function deleteEntriesForVc(
  storage: DashboardLogStorage,
  vcId: string,
): Promise<number> {
  const keys = (await storage.list(DASHBOARD_LOG_KEY_PREFIX)).sort();
  let deleted = 0;
  for (const key of keys) {
    const stored = await storage.get(key);
    if (stored === null) {
      continue;
    }
    const entry = decodeOrUndefined(stored);
    if (entry !== undefined && payloadReferencesVc(entry.payload, vcId)) {
      await storage.delete(key);
      deleted += 1;
    }
  }
  return deleted;
}

/**
 * ユーザー制御 Dashboard ログエントリ（`dashboard-log/`）を一括削除する
 * （Art.17 削除権）。
 *
 * `filter` に一致する（`filter` 省略時は全）エントリを storage から物理削除し、削除件数を返す。
 * 監査用の Art.17 削除記録（`deletion-log/`）は常に対象外（削除の事実を保全するため）。
 *
 * 復号不能（破損）なエントリは、`filter` が全件対象（省略・全フィールド未指定）なら無条件に物理削除する
 * （判定不要で、全消去の意図を満たす）。絞り込み条件がある場合は一致判定できないため削除せず読み飛ばし、
 * 他のエントリの削除を続行する。
 *
 * @param storage エントリの永続化先。
 * @param filter 削除対象を絞り込むフィルタ（省略時は `dashboard-log/` の全エントリ）。
 * @returns 物理削除したエントリ数。
 */
export async function purgeEntries(
  storage: DashboardLogStorage,
  filter?: LogFilter,
): Promise<number> {
  const keys = (await storage.list(DASHBOARD_LOG_KEY_PREFIX)).sort();
  let deleted = 0;
  for (const key of keys) {
    const stored = await storage.get(key);
    if (stored === null) {
      continue;
    }
    const entry = decodeOrUndefined(stored);
    const matches =
      entry === undefined ? isUnrestrictedFilter(filter) : entryMatchesFilter(entry, filter);
    if (matches) {
      await storage.delete(key);
      deleted += 1;
    }
  }
  return deleted;
}

/** {@link collectDeletions} が返す 1 件分（監査記録用の証跡 + 物理削除対象の storage キー）。 */
export interface CollectedDeletion {
  /** 物理削除対象の storage キー（`${DASHBOARD_LOG_KEY_PREFIX}${entry.id}`）。 */
  readonly key: string;
  /** `logEntryDeleted` 監査記録に残す構造的証跡。 */
  readonly record: DeletedLogEntryRecord;
}

/**
 * `predicate` に一致するユーザー制御 Dashboard ログエントリ（`dashboard-log/`）を**削除せずに**列挙し、
 * 監査記録用の構造的証跡（連番・`prevHash`・エントリ自身のハッシュ）を添えて返す（Art.17 個別 / フィルタ
 * 削除）。
 *
 * `DashboardLog.deleteLogEntry` / `deleteLogEntries` が「監査記録を先に追記してから物理削除する」順序
 * （`deleteCredential` と同じ方針）を守れるよう、読み出しと削除を分離する。連番として解釈できない ID の
 * エントリや復号不能なエントリ（storage 破損）は証跡を組み立てられないため対象から除外する（削除も監査記録もしない。
 * 物理削除したいだけなら従来どおり {@link deleteEntriesForVc} / {@link purgeEntries} を使う）。
 *
 * @param storage エントリの永続化先。
 * @param predicate 削除対象の判定関数。
 * @returns 削除対象の storage キーと構造的証跡の組（追記順）。
 */
export async function collectDeletions(
  storage: DashboardLogStorage,
  predicate: (entry: DashboardLogEntry) => boolean,
): Promise<readonly CollectedDeletion[]> {
  const keys = (await storage.list(DASHBOARD_LOG_KEY_PREFIX)).sort();
  const collected: CollectedDeletion[] = [];
  for (const key of keys) {
    const stored = await storage.get(key);
    if (stored === null) {
      continue;
    }
    const entry = decodeOrUndefined(stored);
    if (entry === undefined || !predicate(entry)) {
      continue;
    }
    const seq = seqOf(entry.id);
    if (seq === undefined) {
      // 連番として読めない ID（storage 破損）は証跡を組み立てられない。削除自体をスキップし、
      // `verifyDashboardLogChain` の `malformedId` 検知に判定を委ねる。
      continue;
    }
    collected.push({
      key,
      record: { seq, prevHash: entry.prevHash, entryHash: signingInputHash(entry) },
    });
  }
  return collected;
}

/**
 * `predicate` に一致するエントリを削除し、削除記録（`logEntryDeleted`）を先に追記してから物理削除する
 * （`DashboardLog.deleteLogEntry` / `deleteLogEntries` の共通実装）。
 *
 * **順序が重要。** `deleteCredential`と同じ「記録 → 削除」の順で行う。
 * 逆順にすると、削除は成立したのに署名失敗（`1020`）で記録が残らない不整合が起き、その欠損は
 * `verifyDashboardLogChain` から改ざんと区別できなくなる。
 *
 * `deleteEntriesForVc` / `purgeEntries`（この 2 つは削除記録を残さない）との
 * 違いは、削除する連番・`prevHash`・削除したエントリ自身のハッシュを `deletion-log/` パーティションへ
 * `logEntryDeleted` として JWS 署名付きで残す点である。`dashboard-log-delete.ts` は意図的に残存エントリの
 * `prevHash` を張り替えないため、削除は中間の連番に穴を空ける。署名付きの削除記録が無いと
 * `verifyDashboardLogChain` はこれを攻撃者によるセクション削除と区別できず `sequenceGap` を報告する。
 * 本関数は記録を残すことでユーザー主導の削除であることを事後に証明できるようにする。VC 単位の削除
 * （`deleteEntriesForVc` と対になる `appendDeletionRecord`）とは削除記録の型が異なる（`credentialDeleted`
 * は VC ID の監査、こちらは chain の欠損を説明する構造的証跡）ため、両者は共存できる。
 *
 * @param storage エントリの永続化先。
 * @param predicate 削除対象の判定関数。
 * @param appendDeletionRecord 収集した証跡（`DeletedLogEntryRecord[]`）を `deletion-log/` へ
 *   `logEntryDeleted` として署名付き追記する関数。呼び出し側（`DashboardLog`）が `appendTo` を束縛して渡す。
 * @returns 物理削除したエントリ数。
 * @throws `appendDeletionRecord` が失敗した場合（署名演算の失敗、通常は code `1020`）。
 */
export async function deleteMatchingWithAuditRecord(
  storage: DashboardLogStorage,
  predicate: (entry: DashboardLogEntry) => boolean,
  appendDeletionRecord: (deletions: readonly DeletedLogEntryRecord[]) => Promise<unknown>,
): Promise<number> {
  const collected = await collectDeletions(storage, predicate);
  if (collected.length === 0) {
    return 0;
  }
  await appendDeletionRecord(collected.map((c) => c.record));
  for (const { key } of collected) {
    await storage.delete(key);
  }
  return collected.length;
}
