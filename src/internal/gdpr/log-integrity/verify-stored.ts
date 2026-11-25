/**
 * storage 上の Dashboard ログを**破損を許容しながら**検証する（`DashboardLog.verify` の実装）。
 *
 * **なぜ `DashboardLog.list` を使わないのか。** `list` は 1 件でも復号できないエントリに当たると
 * `VericertsError`（code `6005`。`decodeDashboardLogEntry` の正規化）を投げる。追記（`append`）と
 * 読み出し（`list`）はそれで正しい（壊れたログの上に追記して chain を分岐させない・壊れた履歴を
 * 正常な履歴として UI に見せない）が、検証は**壊れているログこそ対象**なので、同じ厳しさのままでは
 * 例外で読み出しを拒否して、Dashboard UI が破損警告を表示できなくなる。
 *
 * そこで破損の許容は**検証経路だけ**に閉じ込め、復号できなかったエントリを `undecodable` として
 * レポートに載せる。逆に storage アダプタ側で破損を「無い」ことにする（`get` が `null` を返す）のは
 * 採らない。`DashboardLogStorage` の契約では `null` は「不在」であり、破損と混同すると
 * (a) `append` が `prevHash` を計算できずに追記が恒久的に壊れる、(b) 先頭エントリの破損が保持上限に
 * よる正当な切り捨て（`truncated`）に見えて検知の反対になる、という二次被害が出る。
 */

import { decodeDashboardLogEntry } from '../codec.js';
import {
  type DashboardLogStorage,
  tailAnchorKeyFor,
} from '../dashboard-log/dashboard-log-shared.js';
import type { DashboardLogEntry } from '../types.js';
import {
  type DashboardLogDeletionRecords,
  type DashboardLogIssue,
  type DashboardLogTrimWatermark,
  type DashboardLogVerification,
  verifyDashboardLogChain,
} from './chain.js';
import { resolveDeletionRecords } from './deletion-records.js';
import type {
  DashboardLogVerifierKey,
  DashboardLogVerifierKeyResolver,
} from './entry-signature.js';
import { readTailAnchor } from './tail-anchor.js';

/** 破損許容で読んだパーティションの内訳（復号できたエントリと `undecodable` の報告）。 */
interface TolerantPartition {
  entries: DashboardLogEntry[];
  undecodable: DashboardLogIssue[];
}

/**
 * 指定パーティションの保存済みバイト列を**破損を許容して**読み、復号できたエントリと
 * `undecodable` の内訳に分ける（`verifyStoredDashboardLog` / 削除記録の読み取りで共有する）。
 *
 * `list()` / `append()` と違い、1 件の復号失敗で打ち切らない（検証は壊れているログこそ対象のため）。
 */
async function readEntriesTolerantly(
  storage: DashboardLogStorage,
  prefix: string,
): Promise<TolerantPartition> {
  // 連番はゼロ埋めなのでキーの辞書順ソート = 追記順（順序未規定な Storage.list の返り順に依存しない）。
  const keys = (await storage.list(prefix)).sort();
  const entries: DashboardLogEntry[] = [];
  const undecodable: DashboardLogIssue[] = [];

  for (const key of keys) {
    try {
      const stored = await storage.get(key);
      // `null` は「不在」。連番の穴として chain 側が `sequenceGap` で検知する。
      if (stored !== null) entries.push(decodeDashboardLogEntry(stored));
    } catch {
      // 復号失敗（`6005`）だけでなく `get` 自体の失敗もここで畳む。組込先の storage は破損を
      // 例外で知らせる契約（例: extension の base64 破損）であり、ログ全体が読めない場合は上の
      // `list` が先に投げるので、ここに来るのは個別エントリの破損に限られる。
      undecodable.push({ id: key.slice(prefix.length), reason: 'undecodable' });
    }
  }
  return { entries, undecodable };
}

/**
 * 1 パーティションの検証本体（連鎖 + 末尾アンカー）。読み出し済みの内容は `partition` で渡す。
 *
 * 末尾アンカー（`deletion-log/` は）は**どのパーティションにも**ある。読めないアンカーは
 * 「未導入」に畳まず、改ざん（アンカーの破壊で末尾削除を隠す）として報告する。
 */
async function verifyPartition(
  storage: DashboardLogStorage,
  prefix: string,
  partition: TolerantPartition,
  verifierKey: DashboardLogVerifierKey | DashboardLogVerifierKeyResolver,
  watermark: DashboardLogTrimWatermark | undefined,
  deletionRecords: DashboardLogDeletionRecords | undefined,
): Promise<DashboardLogVerification> {
  const { entries, undecodable } = partition;
  const stored = await readTailAnchor(storage, prefix);
  const tailAnchor = stored.kind === 'present' ? stored.anchor : undefined;

  const verified = verifyDashboardLogChain(
    entries,
    verifierKey,
    watermark,
    deletionRecords,
    tailAnchor,
  );
  // 末尾エントリ自体が復号不能なら `undecodable` が報告済み。同じ位置の `tailTruncated` は重複なので外す。
  const brokenIds = new Set(undecodable.map((issue) => issue.id));
  const chainIssues = verified.issues.filter(
    (issue) => !(issue.reason === 'tailTruncated' && brokenIds.has(issue.id)),
  );
  const anchorIssues: DashboardLogIssue[] =
    stored.kind === 'invalid' ? [{ id: tailAnchorKeyFor(prefix), reason: 'tailTruncated' }] : [];
  const issues = [...undecodable, ...chainIssues, ...anchorIssues];
  if (issues.length === 0) return verified;
  // 追記順に整列する（ID はゼロ埋め連番なので辞書順 = 追記順）。壊れたエントリと、その直後に
  // 立つ `sequenceGap` が並んで見えるようにするため。
  return { ...verified, ok: false, issues: issues.sort((a, b) => a.id.localeCompare(b.id)) };
}

/**
 * 指定パーティションの保存済みエントリを読み出し、JWS 署名と Merkle chain を検証する。
 *
 * 復号できたエントリは {@link verifyDashboardLogChain} に渡し、復号できなかったエントリは
 * `undecodable` として `issues` に加える。`count` は復号できたエントリ数（破損分は含まない）で、
 * `truncated` は復号できた先頭エントリについての判定である（破損の有無は `issues` が示す）。
 *
 * @param storage エントリの永続化先。
 * @param prefix 対象パーティションのキー prefix。
 * @param verifierKey 署名検証鍵、または `kid` → 検証鍵の解決関数
 *   （{@link DashboardLogVerifierKeyResolver}）。{@link verifyDashboardLogChain} へそのまま渡す
 *   （署名鍵が交代し得るログではリゾルバを渡し、解決できないエントリは `keyUnresolved` になる）。
 * @param watermark 切り捨ての基準点（{@link DashboardLogTrimWatermark}）。組込先が一度も切り捨てて
 *   いない場合は省略する。省略時は先頭の連番が 0 であることを要求する。
 * @param deletionLogPrefix 個別 / フィルタ削除（Art.17）の削除記録パーティションのキー prefix
 *   （通常 `deletion-log/`）。指定すると同パーティションを破損許容で読み、署名検証済みの削除記録を
 *   {@link verifyDashboardLogChain} へ渡す（{@link resolveDeletionRecords}）。省略時は空扱い（
 *   以前と同一の挙動）。さらに**削除記録パーティション自体にも同じ連鎖検証 + 末尾アンカー照合**を行い
 *   （Art.17 消去証跡の末尾削除・同連番での再追記・欠損・改ざんを検知する）、その `issues` を
 *   ID に `deletionLogPrefix` を前置して（`dashboard-log/` 側の連番と区別して）結果へ合流させる。
 *   削除記録は保持上限による切り捨てを行わないので、ウォーターマークなしで検証する。
 * @returns 検証結果（エントリ単位の破損では例外を投げない）。
 * @throws storage 全体が読めない場合（キー一覧の取得失敗。組込先の storage 実装が投げる例外）。
 */
export async function verifyStoredDashboardLog(
  storage: DashboardLogStorage,
  prefix: string,
  verifierKey: DashboardLogVerifierKey | DashboardLogVerifierKeyResolver,
  watermark?: DashboardLogTrimWatermark,
  deletionLogPrefix?: string,
): Promise<DashboardLogVerification> {
  const partition = await readEntriesTolerantly(storage, prefix);
  if (deletionLogPrefix === undefined) {
    return verifyPartition(storage, prefix, partition, verifierKey, watermark, undefined);
  }
  const deletionPartition = await readEntriesTolerantly(storage, deletionLogPrefix);
  const deletionRecords = resolveDeletionRecords(deletionPartition.entries, verifierKey);
  const verified = await verifyPartition(
    storage,
    prefix,
    partition,
    verifierKey,
    watermark,
    deletionRecords,
  );
  const deletionVerified = await verifyPartition(
    storage,
    deletionLogPrefix,
    deletionPartition,
    verifierKey,
    undefined,
    undefined,
  );
  if (deletionVerified.ok) return verified;
  const deletionIssues = deletionVerified.issues.map((issue) => ({
    ...issue,
    // アンカーキー（`anchor/…`）はそれ自体がパーティションを示すので前置しない。
    id: issue.id.startsWith('anchor/') ? issue.id : `${deletionLogPrefix}${issue.id}`,
  }));
  const issues = [...verified.issues, ...deletionIssues].sort((a, b) => a.id.localeCompare(b.id));
  return { ...verified, ok: false, issues };
}
