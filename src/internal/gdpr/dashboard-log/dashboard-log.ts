/**
 * Dashboard ログの永続化・追記を担う `DashboardLog`。
 *
 * ユーザー制御の Dashboard ログを storage に追記する。各エントリは以下を満たす:
 * - JWS 署名: 正準 payload（`type` / `payload` / `recordedAt` / `prevHash`）を signing-input とする
 *   コンパクト JWS（`header.payload.signature`）。署名鍵は `CredentialSigner` /
 *   `AsyncCredentialSigner` で DI し、生 privateKey を露出しない（issue.ts と同パターン）。
 * - Merkle（ハッシュ）chain: `prevHash` に直前エントリの signing-input の SHA-256（base64url）。先頭は `null`。
 *
 * 削除操作は `deletion-log/` の独立したチェーンに記録する。エクスポートでは通常ログを署名付き NDJSON にし、
 * インポートでは署名とチェーンを検証する。
 *
 * セキュリティ上の注意:
 * - payload・例外に privateKey / seed 等の秘密を含めない。呼び出し側が秘密を含まない payload を渡す責務を持つ。
 */

import { signCompactJwsAsync } from '../../credential/vc/compact-jws.js';
import { type AnyCredentialSigner, buildJwsHeader } from '../../credential/vc/signer.js';
import type { OnWarning } from '../../observability/warning.js';
import { KeyLock } from '../../primitives/key-lock.js';
import { encodeDashboardLogEntry } from '../codec.js';
import { assertValidLogFilter, entryMatchesFilter } from '../log-filter.js';
import type {
  DashboardLogTrimWatermark,
  DashboardLogVerification,
  DashboardLogVerifierKeyResolver,
} from '../log-integrity/chain.js';
import {
  tailAnchorMayAdvance,
  withTailAnchorFollowing,
  writeTailAnchor,
} from '../log-integrity/tail-anchor.js';
import { verifyStoredDashboardLog } from '../log-integrity/verify-stored.js';
import type { DashboardLogEntry, LogEntryType, LogFilter } from '../types.js';
import {
  deleteEntriesForVc,
  deleteMatchingWithAuditRecord,
  payloadReferencesVc,
  purgeEntries,
} from './dashboard-log-delete.js';
import { buildDashboardLogExport } from './dashboard-log-export.js';
import { type DashboardLogVerifierKey, verifyDashboardLogExport } from './dashboard-log-import.js';
import { persistImportedEntries } from './dashboard-log-persist.js';
import { lastSigningInputHash, listPartition } from './dashboard-log-read.js';
import {
  DASHBOARD_LOG_KEY_PREFIX,
  type DashboardLogStorage,
  DELETION_LOG_KEY_PREFIX,
  nextSeq,
  seqToId,
  warnTailAnchorFailed,
} from './dashboard-log-shared.js';

/** `exportLog` が生成する NDJSON（1 行 1 JSON）の MIME タイプ。 */
export const DASHBOARD_LOG_EXPORT_MIME = 'application/x-ndjson';

/**
 * Dashboard ログの追記・読み出しを担う（storage に永続化するためインスタンスはステートレス）。
 */
export class DashboardLog {
  /**
   * @param storage エントリの永続化先。
   * @param now 現在時刻取得関数（既定 `() => new Date()`、テスト用）。
   * @param onWarning 末尾アンカーの書込失敗など、気づきたい失敗の通知先（省略時は何も通知しない）。
   */
  constructor(
    private readonly storage: DashboardLogStorage,
    private readonly now: () => Date = () => new Date(),
    private readonly onWarning?: OnWarning,
  ) {}

  /** パーティション（prefix）単位の追記直列化ロック（並行 `append` の連番衝突を防ぐ）。 */
  private readonly appendLock = new KeyLock();

  /**
   * Dashboard ログにエントリを 1 件追記する（JWS 署名 + Merkle chain）。
   *
   * 既存 ID の最大連番 + 1 を採番し、直前エントリの signing-input SHA-256 を `prevHash` に設定して
   * chain を連結する。`signer` で正準 payload に JWS 署名し、署名済みエントリを storage に永続化する。
   * 同一パーティションへの並行 `append` は内部で直列化され、連番・chain を維持する（単一プロセス内のみ）。
   *
   * @param type エントリ種別。
   * @param payload エントリ固有の内容（秘密を含めない）。
   * @param signer JWS 署名鍵（`CredentialSigner` / `AsyncCredentialSigner`）。
   * @returns 追記した署名済みエントリ。
   * @throws 署名演算が失敗した場合（VericertsError、code `1020`）。
   */
  async append(
    type: LogEntryType,
    payload: Readonly<Record<string, unknown>>,
    signer: AnyCredentialSigner,
  ): Promise<DashboardLogEntry> {
    return this.appendTo(DASHBOARD_LOG_KEY_PREFIX, type, payload, signer);
  }

  /**
   * 指定パーティションにエントリを 1 件追記する（`append` / `appendDeletionRecord` の共通実装）。
   * 採番 → 署名(await) → set の間に他の追記が割り込むと同一連番で上書きし監査エントリが消失するため、
   * prefix 単位で直列化する。
   */
  private appendTo(
    prefix: string,
    type: LogEntryType,
    payload: Readonly<Record<string, unknown>>,
    signer: AnyCredentialSigner,
  ): Promise<DashboardLogEntry> {
    return this.appendLock.run(prefix, async () => {
      // 順序未規定の Storage.list に依存しないよう、ゼロ埋めキーを辞書順ソートして末尾を特定する。
      const keys = (await this.storage.list(prefix)).sort();
      // 件数ではなく最大連番 + 1 を採る（低番のみ削除された後も ID が衝突しない）。
      const seq = nextSeq(keys);
      const prevHash = keys.length === 0 ? null : await lastSigningInputHash(this.storage, keys);
      // 末尾アンカー（`deletion-log/` は）は両パーティションで維持する。
      const anchored = await tailAnchorMayAdvance(this.storage, prefix, keys);

      const recordedAt = this.now().toISOString();
      // 署名対象は正準 payload（署名・chain の対象を明示的に固定する）。
      const signedPart = { type, payload, recordedAt, prevHash };
      const jws = await signCompactJwsAsync(buildJwsHeader(signer, 'JWT'), signedPart, signer);

      const id = seqToId(seq);
      const entry: DashboardLogEntry = { id, type, recordedAt, payload, prevHash, signature: jws };
      await this.storage.set(`${prefix}${id}`, encodeDashboardLogEntry(entry));
      // 末尾アンカーは連鎖が整合している間だけ前進させる（巻き戻された末尾を追認しない）。
      // エントリは永続化済みなので、アンカー書込の失敗で追記全体を失敗扱いにしない（呼び出し側が
      // 再送して二重記録になる）。アンカーが遅れるだけなら検証は通り、次の追記で追いつく。
      // 結論（追記の成功）は変えないが、アンカーが遅れたまま気づかれないのは避けたいので `onWarning` に流す。
      if (anchored) {
        await writeTailAnchor(this.storage, prefix, entry).catch((e: unknown) =>
          warnTailAnchorFailed(this.onWarning, e),
        );
      }
      return entry;
    });
  }

  /**
   * Art.17 削除の監査記録を別ログパーティション（`deletion-log/`）に追記する。
   *
   * 削除される VC の `dashboard-log/` エントリとは独立したチェーンに `type: "credentialDeleted"` を JWS
   * 署名付きで残す（`deleteEntriesForVc` / `purgeDashboardLog` の削除対象外）。payload は VC ID のみ。
   *
   * @param vcId 物理削除した VC の ID。
   * @param signer JWS 署名鍵（`CredentialSigner` / `AsyncCredentialSigner`）。
   * @returns 追記した署名済みエントリ。
   * @throws 署名演算が失敗した場合（VericertsError、code `1020`）。
   */
  async appendDeletionRecord(
    vcId: string,
    signer: AnyCredentialSigner,
  ): Promise<DashboardLogEntry> {
    return this.appendTo(DELETION_LOG_KEY_PREFIX, 'credentialDeleted', { vcId }, signer);
  }

  /**
   * 特定 VC を参照するユーザー制御 Dashboard ログエントリ（`dashboard-log/`）を物理削除する
   * （Art.17 忘れられる権利）。実装は `dashboard-log-delete.ts` に委譲する。
   * 復号不能（破損）なエントリは参照判定できないため読み飛ばし、残りの削除を続行する。
   *
   * `deleteLogEntries` と同じく削除証跡（`logEntryDeleted`）を先に残す（無いと `verify` が `sequenceGap` を誤報告）。
   * @param vcId 削除対象 VC の ID。
   * @param signer 削除証跡の署名鍵。
   * @returns 物理削除したエントリ数。
   * @throws 署名演算が失敗した場合（VericertsError、code `1020`。何も削除しない）。
   */
  async deleteEntriesForVc(vcId: string, signer: AnyCredentialSigner): Promise<number> {
    return this.followingTail(async () => {
      const audited = await this.deleteMatching(
        (e) => payloadReferencesVc(e.payload, vcId),
        signer,
      );
      // 連番として読めない ID は証跡を組み立てられないが、消去義務の対象なので証跡なしで削除する。
      return audited + (await deleteEntriesForVc(this.storage, vcId));
    });
  }

  /**
   * ユーザー制御 Dashboard ログエントリを一括削除する（Art.17 削除権）。
   * 復号不能（破損）なエントリは、`filter` が全件対象なら無条件に物理削除し、絞り込み条件があれば
   * 読み飛ばして残りの削除を続行する。
   *
   * @param filter 削除対象を絞り込むフィルタ（省略時は `dashboard-log/` の全エントリ）。
   * @returns 物理削除したエントリ数。
   */
  async purge(filter?: LogFilter): Promise<number> {
    assertValidLogFilter(filter);
    return this.followingTail(() => purgeEntries(this.storage, filter));
  }

  /** ID 指定で 1 件削除する（Art.17）。詳細は {@link deleteMatchingWithAuditRecord}。 */
  async deleteLogEntry(id: string, signer: AnyCredentialSigner): Promise<boolean> {
    return (
      (await this.followingTail(() => this.deleteMatching((entry) => entry.id === id, signer))) > 0
    );
  }

  /** フィルタ削除（Art.17 削除権）。詳細は {@link deleteMatchingWithAuditRecord}。 */
  async deleteLogEntries(
    filter: LogFilter | undefined,
    signer: AnyCredentialSigner,
  ): Promise<number> {
    assertValidLogFilter(filter);
    return this.followingTail(() =>
      this.deleteMatching((entry) => entryMatchesFilter(entry, filter), signer),
    );
  }

  /** {@link deleteLogEntry} / {@link deleteLogEntries} の共通実装（呼び出し側が {@link followingTail} で包む）。 */
  private deleteMatching(
    predicate: (entry: DashboardLogEntry) => boolean,
    signer: AnyCredentialSigner,
  ): Promise<number> {
    return deleteMatchingWithAuditRecord(this.storage, predicate, (deletions) =>
      this.appendTo(DELETION_LOG_KEY_PREFIX, 'logEntryDeleted', { deletions }, signer),
    );
  }

  /** 削除を追記と同じロックの下で行い、アンカーを残存末尾へ追従させる（`withTailAnchorFollowing`）。 */
  private followingTail<T>(op: () => Promise<T>): Promise<T> {
    return this.appendLock.run(DASHBOARD_LOG_KEY_PREFIX, () =>
      withTailAnchorFollowing(this.storage, DASHBOARD_LOG_KEY_PREFIX, op),
    );
  }

  /**
   * ユーザー制御 Dashboard ログを JWS 署名付き NDJSON 形式でエクスポートする
   * （Art.15 アクセス権、Art.20 データポータビリティ）。
   *
   * `filter` に一致する（省略時は全）`dashboard-log/` エントリを追記順に 1 行 1 JSON で連結し、末尾に
   * Merkle ルートハッシュ行（`{ "merkleRoot", "count" }`）を付与した NDJSON を返す。各行は署名済みの
   * 正準 payload をそのまま含むため、署名と `prevHash` chain を独立に検証できる。0 件時は `merkleRoot: null`。監査用の削除記録は対象外。
   * chain に欠損があるとき（絞り込み・削除済み）は `partial: true` を付ける（`dashboard-log-export.ts`）。
   *
   * @param filter エクスポート対象を絞り込むフィルタ（省略時は `dashboard-log/` の全エントリ）。
   * @returns NDJSON テキスト（各行が JWS 署名付きエントリ、末尾行が Merkle ルートハッシュ）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async exportLog(filter?: LogFilter): Promise<string> {
    assertValidLogFilter(filter);
    const entries = (await this.list()).filter((entry) => entryMatchesFilter(entry, filter));
    return buildDashboardLogExport(entries);
  }

  /**
   * `exportLog` が生成した JWS 署名付き NDJSON を検証してユーザー制御 Dashboard ログへインポートする
   * （Art.20 データポータビリティ）。
   *
   * 各エントリの JWS 署名・Merkle prevHash chain・末尾ルートハッシュ行をすべて検証し、1 つでも失敗すれば
   * 拒否する（`verifyDashboardLogExport`）。検証済みエントリは署名・`prevHash` を保ったまま（再署名せず）
   * 永続化する。既存 chain との連結を避けるため空の `dashboard-log/` にのみ許可し（既存エントリがあれば
   * `GDPR_DASHBOARD_LOG_NOT_EMPTY`(10604)）、監査用の Art.17 削除記録（`deletion-log/`）は対象にしない。
   *
   * @param ndjson `exportLog` が生成した NDJSON テキスト（各行が JWS 署名付きエントリ、末尾行がルートハッシュ）。
   * @param verifierKey 署名検証鍵（署名時のペルソナ / エフェメラル公開鍵）。
   * @returns インポートしたエントリ数。
   * @throws NDJSON 形式不正・ルートハッシュ行欠落の場合（VericertsError、code `2001`）、
   *         署名検証失敗・Merkle chain / ルートハッシュ不一致の場合（code `3010`）、
   *         既存ログが空でない場合（code `10604`）。
   */
  async importLog(ndjson: string, verifierKey: DashboardLogVerifierKey): Promise<number> {
    // 検証を先に行い、改ざんされた入力を storage に触れさせない。
    const entries = verifyDashboardLogExport(ndjson, verifierKey);
    // 空判定→連番書き込みを append と同じ appendLock で原子化する（連番衝突による上書きを防ぐ）。
    return this.appendLock.run(DASHBOARD_LOG_KEY_PREFIX, () =>
      persistImportedEntries(this.storage, entries),
    );
  }

  /**
   * 保存済み Dashboard ログエントリを追記順（連番昇順）で返す。
   *
   * @returns エントリの配列（該当なしは空配列）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async list(): Promise<DashboardLogEntry[]> {
    return listPartition(this.storage, DASHBOARD_LOG_KEY_PREFIX);
  }

  /**
   * 保存済み Dashboard ログの JWS 署名と Merkle chain を検証する。
   *
   * 見つかった破損はレポートの `issues` に列挙する。復号できないエントリは `undecodable` として扱う。
   *
   * **`watermark`**（{@link DashboardLogTrimWatermark}、省略時は先頭連番 0 を要求）・**`verifierKey` の
   * 鍵リゾルバ形（`kid` → 検証鍵）・削除記録との照合** の各判定ロジックと判断記録は、
   * それぞれ委譲先の `log-integrity/chain.js`（`verifyDashboardLogChain`）と `verify-stored.ts`
   * （`resolveDeletionRecords`）を参照。
   *
   * @param verifierKey 署名検証鍵（追記時のペルソナ公開鍵）、または `kid` → 検証鍵の解決関数。
   * @param watermark 切り捨ての基準点。一度も切り捨てていない場合は省略する。
   * @returns 検証結果（`ok` / `issues` / `truncated` / `merkleRoot`）。
   */
  async verify(
    verifierKey: DashboardLogVerifierKey | DashboardLogVerifierKeyResolver,
    watermark?: DashboardLogTrimWatermark,
  ): Promise<DashboardLogVerification> {
    return verifyStoredDashboardLog(
      this.storage,
      DASHBOARD_LOG_KEY_PREFIX,
      verifierKey,
      watermark,
      DELETION_LOG_KEY_PREFIX,
    );
  }

  /**
   * Art.17 削除監査記録（`deletion-log/`）を追記順（連番昇順）で返す。
   *
   * @returns 削除監査エントリの配列（該当なしは空配列）。
   * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
   */
  async listDeletionRecords(): Promise<DashboardLogEntry[]> {
    return listPartition(this.storage, DELETION_LOG_KEY_PREFIX);
  }
}
