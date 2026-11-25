/**
 * 保存済み Dashboard ログの JWS 署名・Merkle chain 検証。
 *
 * 保存済みログは破損を検知しても読み取りを継続し、問題の一覧を {@link DashboardLogVerification} として返す。
 * 署名付き NDJSON のインポートでは、検証に失敗したデータの取り込みを拒否する。
 *
 * 検証項目:
 *
 * 1. **JWS 署名**: 署名対象 payload（`type` / `payload` / `recordedAt` / `prevHash`）が本文フィールドと
 *    一致することを確認したうえで検証鍵で署名を検証する（`verifyEntrySignature`。エクスポート検証と
 *    同一実装を共有する）。
 * 2. **Merkle（ハッシュ）chain**: `prevHash` が直前エントリの signing-input SHA-256（base64url）と
 *    一致する（`append` / `exportLog` と同一計算）。
 * 3. **連番の連続性**: エントリ ID のゼロ埋め連番が 1 ずつ増える。
 *
 * **保持上限による先頭の切り捨てと、悪意ある削除を区別する。** 組込先が古いエントリを保持上限で
 * 捨てると、残った先頭エントリの `prevHash` は `null` にならず直前エントリも手元に無いため chain を
 * 照合できない。これを改ざんとして報告すると警告が常時点灯して意味を失うので、正当な切り捨ては
 * {@link DashboardLogVerification.truncated} として扱い `ok` を落とさない。
 *
 * 先頭に欠損がある場合、残った連番だけでは保持上限による正当な切り捨てと区別できない。
 *
 * そこで**切り捨てのウォーターマーク**（{@link DashboardLogTrimWatermark}）を組込先が永続化し、
 * それを {@link verifyDashboardLogChain} の第 3 引数として渡して照合する。渡された場合は残存先頭が
 * 「最後に切り捨てたエントリの次」であることを連番と `prevHash` の両方で確かめ、**照合が通ったときに
 * 限り** `truncated` で `ok` を維持する。連番だけでは担保にならない（`entry.id` は署名対象外なので
 * 連番は付け替えられる）ため、`prevHash` の一致が本質的な担保である。
 *
 * 一方、先頭に隣接しない**中間セクションの削除**は従来どおり連番に穴を空けるため `sequenceGap` として
 * 検知される（`dashboard-log-delete.ts` が残存エントリの `prevHash` を当時の値のまま保持するので、
 * 削除区間の前後で chain も切れて二重に検知される）。
 *
 * **署名鍵は 1 本に固定できない。** 保存済みログには、K3 Passkey-PRF 由来のログ専用鍵・PRF
 * 非対応時の seed 由来代替鍵・従来のアクティブペルソナ鍵（K2 由来・`ES256K`）で署名された
 * エントリが混在し得る。単一の {@link DashboardLogVerifierKey} で
 * 全件を検証すると当時の鍵で正しく署名されたエントリまで `signatureInvalid` になり、警告が常時点灯して
 * 検知が意味を失う。そこで {@link verifyDashboardLogChain} の第 2 引数は検証鍵のほかに
 * {@link DashboardLogVerifierKeyResolver}（`kid` → 鍵）も受け付け、エントリごとに署名時点の鍵で検証する。
 * `kid` は `extractKid` が JWS ヘッダから取り出し、旧 K2 エントリは `kid` を持たないため `undefined` が
 * 解決キーになる。**リゾルバが鍵を返せないエントリは fail-closed** で {@link DashboardLogIssueReason} の
 * `keyUnresolved` として報告する（検証を飛ばして正常扱いにはしない。エントリ添付の公開鍵も信頼しない）。
 *
 * セキュリティ上の注意:
 * - `issues` には検知した位置（エントリ ID）と理由だけを載せ、payload・署名バイト列は載せない。
 */

import { signingInputHash } from '../dashboard-log/dashboard-log-shared.js';
import type { DashboardLogEntry } from '../types.js';
import {
  type DashboardLogDeletionRecords,
  resolveDeletionRecords,
  resolveDeletionSpan,
} from './deletion-records.js';
import {
  type DashboardLogVerifierKey,
  type DashboardLogVerifierKeyResolver,
  extractKid,
  seqOf,
  verifyEntrySignature,
} from './entry-signature.js';
import { snapshotDashboardLogEntry } from './entry-snapshot.js';
import { type DashboardLogTailAnchor, verifyTailAnchor } from './tail-anchor.js';

/** 検証鍵・鍵リゾルバの型を再エクスポートする（`verifyDashboardLogChain` の引数型として必要になるため）。 */
export type { DashboardLogVerifierKey, DashboardLogVerifierKeyResolver };
/**
 * 削除記録の型・解決関数を再エクスポートする。実体は `deletion-records.js` に切り出したが、
 * `DashboardLog` / 公開バレルは従来どおり本モジュールから import する（`verifyDashboardLogChain` の
 * 引数型と対になるため）。
 */
export { type DashboardLogDeletionRecords, resolveDeletionRecords };

/** 検知した破損の理由。 */
export type DashboardLogIssueReason =
  /** JWS 署名が無効、または署名対象 payload が本文フィールドと一致しない（改ざん）。 */
  | 'signatureInvalid'
  /** `prevHash` が直前エントリの signing-input ハッシュと一致しない（chain 断絶）。 */
  | 'chainBroken'
  /** 連番に穴がある（エントリの欠損 / 中間セクションの削除）。 */
  | 'sequenceGap'
  /** エントリ ID がゼロ埋め連番の形をしていない（storage の破損）。 */
  | 'malformedId'
  /**
   * storage 上のバイト列をエントリとして復号できない（storage の破損 / OS 経由の直接書換）。
   *
   * `verifyDashboardLogChain` は**復号済み**エントリ列だけを見るので、この理由を立てるのは読み出し側
   * （`verify-stored.ts` の `verifyStoredDashboardLog`）である。復号できなかったエントリは chain から
   * 抜け落ちるため、直後のエントリに `sequenceGap` が併せて立つ。
   */
  | 'undecodable'
  /**
   * 署名時点の検証鍵を解決できない（{@link DashboardLogVerifierKeyResolver} が `undefined` を返した）。
   *
   * `signatureInvalid`（「**誰が署名したかは分かる**が署名が暗号学的に無効」= 改ざんの証跡）とは
   * 別の事象で、こちらは「**誰が署名したのか分からない**」— ヘッダの `kid` が組込先の既知鍵集合に
   * 無い（鍵履歴の欠落・別ウォレットのエントリの混入・`kid` を持たない旧 K2 エントリに対する旧鍵の
   * 未設定）。この理由が立つエントリでは署名検証を試みない（照合する鍵が無い）。
   *
   * 双方とも `ok` を落とす（fail-closed。鍵が無いことを理由に検証を飛ばして正常扱いにはしない）が、
   * 理由を分けることで Dashboard UI は「改ざんの疑い」と「鍵履歴を復元すれば検証できる」を区別して
   * 案内できる。
   */
  | 'keyUnresolved'
  /**
   * 末尾（最新側）のエントリが削除・差し替えられている。末尾アンカー
   * （{@link DashboardLogTailAnchor}）が指す最終エントリより保存済みの末尾が後退している、または同じ連番の
   * エントリのハッシュが異なる（削除後に別内容を追記して履歴を書き換えた）、あるいはアンカー自体が
   * 読めない。連番にも `prevHash` にも穴を作らない欠損なので `sequenceGap` / `chainBroken` では出ない。
   * `id` はアンカーが指す連番（アンカー自体が壊れているときは storage キー）。
   */
  | 'tailTruncated';

/**
 * 保持上限による切り捨ての基準点（ウォーターマーク）。
 *
 * 組込先が古いエントリを捨てるたびに更新して永続化し、検証時に
 * {@link verifyDashboardLogChain} へ渡す。これが「どこまでが正当な切り捨てか」の唯一の根拠になる。
 *
 * **算出にハッシュ計算は要らない。** 切り捨て直後の残存先頭エントリの `prevHash` は、定義上
 * **最後に切り捨てたエントリの signing-input ハッシュそのもの**であり、その連番は「切り捨てた
 * 最終エントリの連番 + 1」である。したがって組込先は残存先頭を 1 件読むだけで
 * `{ seq: 残存先頭の連番 - 1, prevHash: 残存先頭の prevHash }` を得られる（`signingInputHash` を
 * 組込先へ公開する必要が無い）。この同一性が下の照合が成り立つ根拠である。
 */
export interface DashboardLogTrimWatermark {
  /** 最後に切り捨てたエントリの連番。 */
  readonly seq: number;
  /** 最後に切り捨てたエントリの signing-input の SHA-256（base64url）= 残存先頭の `prevHash`。 */
  readonly prevHash: string;
}

/** 検知した破損 1 件。 */
export interface DashboardLogIssue {
  /** 破損を検知したエントリの ID。 */
  readonly id: string;
  /** 破損の理由。 */
  readonly reason: DashboardLogIssueReason;
}

/** 保存済み Dashboard ログの検証結果。Dashboard の警告表示に利用できる。 */
export interface DashboardLogVerification {
  /** 破損を検知しなかったか（`issues` が空か）。 */
  readonly ok: boolean;
  /** 検証したエントリ数。 */
  readonly count: number;
  /**
   * 先頭より前のエントリが存在しない状態か（保持上限による正当な切り捨て）。
   *
   * `true` になるのは**ウォーターマークとの照合が通った場合だけ**である（照合できない切り捨ては
   * `sequenceGap` として `issues` に載る）。したがって `true` でも `ok` は `false` にならず、UI は
   * 「これより古い記録は保持上限で失われている」旨を改ざん警告とは区別して示せる。
   */
  readonly truncated: boolean;
  /**
   * 最終エントリの signing-input の SHA-256（base64url）。0 件時は `null`。
   *
   * `exportLog` のルートハッシュと同一計算。末尾エントリの削除は連番にも chain にも穴を作らないため、
   * この値だけでは検知できない。検知は組込先が保存する末尾アンカー（{@link DashboardLogTailAnchor}、
   * `DashboardLog` が自動で維持する）との照合で行い、さらに storage の外へ保全した値と突き合わせれば
   * アンカーごとの巻き戻しも検知できる。
   */
  readonly merkleRoot: string | null;
  /** 検知した破損（追記順）。空なら改ざん・欠損なし。 */
  readonly issues: readonly DashboardLogIssue[];
}

/**
 * 保存済み Dashboard ログエントリ列の JWS 署名と Merkle chain を検証する。
 *
 * @param entries 追記順（連番昇順）のエントリ列。`DashboardLog.list` の戻り値をそのまま渡す。
 * @param verifierKeyOrResolver 署名検証鍵、または `kid` → 検証鍵の解決関数
 *   （{@link DashboardLogVerifierKeyResolver}）。単一の鍵を渡すと全エントリを同じ鍵で検証する
 *   （従来と同一の挙動）。署名鍵が交代し得るログ（K3 専用鍵の更新・PRF 非対応時の代替鍵・
 *   従来の旧 K2 エントリの混在）ではリゾルバを渡す。鍵を解決できないエントリは `keyUnresolved`
 *   として報告し、`ok` を落とす（fail-closed）。
 * @param watermark 切り捨ての基準点（{@link DashboardLogTrimWatermark}）。組込先が一度も切り捨てて
 *   いない場合は省略する。省略時は先頭の連番が 0 であることを要求し、`0` でなければ
 *   `sequenceGap` として報告する（先頭ごとの削除を正当な切り捨てに偽装させない）。
 * @param deletionRecords 個別 / フィルタ削除（Art.17）の署名検証済み構造的証跡
 *   （{@link resolveDeletionRecords}）。省略時は空扱い（削除記録を持たない欠損はすべて `sequenceGap`
 *   になる。従来と同一の挙動）。
 * @param tailAnchor 末尾アンカー（{@link DashboardLogTailAnchor}）。指定すると、最終エントリが
 *   アンカーより後退・差し替わっていないかを照合し、食い違いを `tailTruncated` として報告する。
 *   省略時は末尾を照合しない（従来と同一の挙動）。
 * @returns 検証結果（例外は投げない）。
 */
export function verifyDashboardLogChain(
  entries: readonly DashboardLogEntry[],
  verifierKeyOrResolver: DashboardLogVerifierKey | DashboardLogVerifierKeyResolver,
  watermark?: DashboardLogTrimWatermark,
  deletionRecords: DashboardLogDeletionRecords = new Map(),
  tailAnchor?: DashboardLogTailAnchor,
): DashboardLogVerification {
  const issues: DashboardLogIssue[] = [];
  let previous: DashboardLogEntry | undefined;
  let previousSeq: number | undefined;
  let truncated = false;
  // 呼び出し側が組んだ素のエントリが `Object.prototype` の汚染値を拾わないよう、own の写しへ畳んでから読む。
  const snapshots = entries.map(snapshotDashboardLogEntry);

  for (const entry of snapshots) {
    const seq = seqOf(entry.id);
    const contiguous = seq !== undefined && previousSeq !== undefined && seq === previousSeq + 1;

    if (seq === undefined) {
      issues.push({ id: entry.id, reason: 'malformedId' });
    } else if (previousSeq === undefined) {
      // 先頭エントリ。ここが「正当な切り捨て」と「先頭ごとの削除」の分岐点である。
      if (
        watermark !== undefined &&
        seq === watermark.seq + 1 &&
        entry.prevHash === watermark.prevHash
      ) {
        // ウォーターマークとの照合が通った（残存先頭 = 最後に切り捨てたエントリの次）。連番と
        // `prevHash` の**両方**を見る: `entry.id` は署名対象外で連番を付け替えられるため、担保に
        // なるのは `prevHash` の一致（= 切り捨て時に記録した signing-input ハッシュ）である。
        truncated = true;
      } else if (
        watermark !== undefined &&
        seq > watermark.seq + 1 &&
        resolveDeletionSpan(watermark.seq + 1, seq, watermark.prevHash, deletionRecords) ===
          entry.prevHash
      ) {
        // trim済み（watermarkあり）の残存先頭を、さらに個別 / フィルタ削除で削除したケース。
        // 削除区間の起点は「trimされた末尾の次」であって chain の起点（seq 0 / prevHash null）では
        // ないため、削除証跡の照合も watermark.seq + 1 / watermark.prevHash を起点に行う必要がある
        // （0 起点で照合すると seq 0 の削除証跡が存在せず必ず不一致になり、恒久的な sequenceGap になる）。
        truncated = true;
      } else if (seq > 0 && resolveDeletionSpan(0, seq, null, deletionRecords) === entry.prevHash) {
        // 個別 / フィルタ削除で先頭側の連番がまとめてユーザー操作により削除された。
        // 削除記録が chain 起点（`null`）から残存先頭まで矛盾なくつながるので sequenceGap にしない。
      } else if (seq > 0) {
        // 切り捨て・削除のいずれの記録でも説明できないのに前方が無い = 先頭ごと削除された疑い。
        // `truncated` に逃がすと、隠したいエントリを前方ごと削除する攻撃が素通りする（docblock の実測例）。
        issues.push({ id: entry.id, reason: 'sequenceGap' });
      } else if (entry.prevHash !== null) {
        // 連番 0 は chain の起点なので `prevHash` は null でなければならない。
        issues.push({ id: entry.id, reason: 'chainBroken' });
      }
    } else if (!contiguous) {
      // 連番の穴。削除記録で矛盾なく説明できれば個別 / フィルタ削除、できなければ
      // エントリの欠損として報告する。
      const explained =
        seq > previousSeq &&
        previous !== undefined &&
        resolveDeletionSpan(previousSeq + 1, seq, signingInputHash(previous), deletionRecords) ===
          entry.prevHash;
      if (!explained) {
        issues.push({ id: entry.id, reason: 'sequenceGap' });
      }
    }

    // `prevHash` の照合は連番が連続するときだけ行う。穴が空いた区間は直前エントリが手元に無く、
    // 照合しても必ず不一致になるだけで `sequenceGap` に上乗せの情報を持たない。
    if (contiguous && previous !== undefined && entry.prevHash !== signingInputHash(previous)) {
      issues.push({ id: entry.id, reason: 'chainBroken' });
    }

    // 署名時点の鍵を決める。単一の鍵を渡された場合は `kid` を見ない（従来と同一の挙動）。
    const verifierKey =
      typeof verifierKeyOrResolver === 'function'
        ? verifierKeyOrResolver(extractKid(entry))
        : verifierKeyOrResolver;

    if (verifierKey === undefined) {
      // 照合する鍵が無いので署名検証は試みない。黙って飛ばすと改ざん検知が抜けるため報告する。
      issues.push({ id: entry.id, reason: 'keyUnresolved' });
    } else if (!verifyEntrySignature(entry, verifierKey)) {
      issues.push({ id: entry.id, reason: 'signatureInvalid' });
    }

    previous = entry;
    previousSeq = seq;
  }

  // 末尾側の欠損。上のループは先頭・中間の欠損しか見られない。
  const tailIssue = tailAnchor === undefined ? undefined : verifyTailAnchor(snapshots, tailAnchor);
  if (tailIssue !== undefined) issues.push(tailIssue);

  const last = snapshots[snapshots.length - 1];
  return {
    ok: issues.length === 0,
    count: snapshots.length,
    truncated,
    merkleRoot: last === undefined ? null : signingInputHash(last),
    issues,
  };
}
