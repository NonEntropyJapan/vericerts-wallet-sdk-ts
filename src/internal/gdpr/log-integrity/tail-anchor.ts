/**
 * Dashboard ログの**末尾アンカー**（`deletion-log/` にも同じ仕組みを適用）。ログ末尾（最新側）のエントリ削除を検知する。
 *
 * `verifyDashboardLogChain` は先頭側の欠損にはウォーターマーク（`DashboardLogTrimWatermark`）という基準点を
 * 持つが、末尾側には基準点が無かった。末尾 N 件を storage から消しても連番・`prevHash` に穴は空かず、
 * 続く `append` は「最大連番 + 1」「直前生存エントリのハッシュ」で採番するため、書き換え後の履歴が最初から
 * そうだったかのように整合した chain になる（履歴の巻き戻し + 書き換え）。ログ単体では原理的に検知できない
 * ので、**ログのエントリとは別の storage キー**（{@link DASHBOARD_LOG_TAIL_ANCHOR_KEY}）に「最後に確定した
 * 末尾」（連番 + signing-input ハッシュ）を固定して照合する。
 *
 * 維持は `DashboardLog`（追記 / インポート / 削除）が行う。**アンカーは整合している間だけ前進する**:
 * 追記時に現在の末尾がアンカーと食い違っていたら（= 末尾が巻き戻された）、追記は成立させるがアンカーは
 * 据え置く。更新してしまうと巻き戻しを正史として追認し、以後 `verify` が検知できなくなるため。据え置かれた
 * アンカーは `verify` が `tailTruncated` を報告し続ける（全件削除 = `purge()` が回復手段）。
 *
 * **限界**: アンカー自体も storage 上のレコードなので、エントリとアンカーを**両方**同じ時点へ巻き戻せる、
 * あるいはアンカーを消して未導入の状態に戻せる書込者は防げない（アンカー未保存のログは従来どおり検証対象外
 * で、次の追記が現在の末尾を採用する）。それを超える保証が要るなら、`verify` 結果の `merkleRoot` /
 * `exportLog` のルートハッシュを storage の外へ保全して突き合わせる。
 */

import { ownProperty } from '../../prototype-safety/own-property.js';
import { decodeDashboardLogEntry } from '../codec.js';
import {
  type DashboardLogStorage,
  seqToId,
  signingInputHash,
  tailAnchorKeyFor,
} from '../dashboard-log/dashboard-log-shared.js';
import type { DashboardLogEntry } from '../types.js';
import type { DashboardLogIssue } from './chain.js';
import { seqOf } from './entry-signature.js';

/** 末尾アンカー: 最後に確定した末尾エントリの連番とその signing-input の SHA-256（base64url）。 */
export interface DashboardLogTailAnchor {
  /** 末尾エントリの連番。 */
  readonly seq: number;
  /** 末尾エントリの signing-input の SHA-256（base64url。`verify` の `merkleRoot` と同一計算）。 */
  readonly hash: string;
}

/** storage から読んだアンカーの状態。壊れていれば `invalid`（`absent` に畳まない = fail-closed）。 */
export type StoredTailAnchor =
  | { readonly kind: 'absent' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'present'; readonly anchor: DashboardLogTailAnchor };

/** storage の末尾アンカーを読む（`prefix` のパーティション用）。読み出し失敗・形式不正は `invalid`（未導入の `absent` とは区別する）。 */
export async function readTailAnchor(
  storage: DashboardLogStorage,
  prefix: string,
): Promise<StoredTailAnchor> {
  let stored: Uint8Array | null;
  try {
    stored = await storage.get(tailAnchorKeyFor(prefix));
  } catch {
    return { kind: 'invalid' };
  }
  if (stored === null) return { kind: 'absent' };
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(stored));
    if (typeof parsed === 'object' && parsed !== null) {
      // own 限定で読む。保存済みアンカーが省略したキーを `Object.prototype` の汚染値で補って、偽の末尾アンカーを作らない。
      const seq = ownProperty<unknown>(parsed, 'seq');
      const hash = ownProperty<unknown>(parsed, 'hash');
      if (typeof seq === 'number' && Number.isSafeInteger(seq) && seq >= 0) {
        if (typeof hash === 'string' && hash !== '') {
          return { kind: 'present', anchor: { seq, hash } };
        }
      }
    }
  } catch {
    // 下の `invalid` へ落とす。
  }
  return { kind: 'invalid' };
}

/** 末尾エントリを `prefix` のパーティションのアンカーとして保存する（連番として読めない ID なら何もしない）。 */
export async function writeTailAnchor(
  storage: DashboardLogStorage,
  prefix: string,
  entry: DashboardLogEntry,
): Promise<void> {
  const seq = seqOf(entry.id);
  if (seq === undefined) return;
  const anchor: DashboardLogTailAnchor = { seq, hash: signingInputHash(entry) };
  await storage.set(tailAnchorKeyFor(prefix), new TextEncoder().encode(JSON.stringify(anchor)));
}

/**
 * 復号済みエントリ列の末尾がアンカーと整合するかを検証する（`verifyDashboardLogChain` の第 5 引数）。
 *
 * - アンカー位置のエントリが残っていて**ハッシュが違う** → 差し替え（削除後に別内容を追記した巻き戻し）。
 * - アンカー位置のエントリが無く、**最終連番がアンカーより小さい**（空を含む）→ 末尾の削除。
 * - アンカー位置が無いが最終連番がそれ以上 → 保持上限による先頭側の切り捨て / 削除記録つきの削除で、
 *   欠損は `sequenceGap` 側が説明・報告するので重ねて報告しない。
 */
export function verifyTailAnchor(
  entries: readonly DashboardLogEntry[],
  anchor: DashboardLogTailAnchor,
): DashboardLogIssue | undefined {
  const atAnchor = entries.find((entry) => seqOf(entry.id) === anchor.seq);
  if (atAnchor !== undefined) {
    return signingInputHash(atAnchor) === anchor.hash
      ? undefined
      : { id: atAnchor.id, reason: 'tailTruncated' };
  }
  const last = entries[entries.length - 1];
  const missing: DashboardLogIssue = { id: seqToId(anchor.seq), reason: 'tailTruncated' };
  if (last === undefined) return missing;
  const lastSeq = seqOf(last.id);
  // 連番として読めない末尾 ID は `malformedId` が報告済みなので重ねて報告しない。
  return lastSeq !== undefined && lastSeq < anchor.seq ? missing : undefined;
}

/**
 * 現在の storage 末尾がアンカーと整合するか（追記・削除の**前**に呼ぶ）。{@link verifyTailAnchor} と同じ
 * 判定を、全件を復号せず「最終キーの連番 + アンカー位置の 1 件」だけで行う。
 *
 * @param sortedKeys 対象パーティションの storage キー（辞書順ソート済み）。
 */
async function tailHolds(
  storage: DashboardLogStorage,
  prefix: string,
  sortedKeys: readonly string[],
  anchor: DashboardLogTailAnchor,
): Promise<boolean> {
  const lastKey = sortedKeys[sortedKeys.length - 1];
  const lastSeq = lastKey === undefined ? undefined : seqOf(lastKey);
  if (lastSeq === undefined || lastSeq < anchor.seq) return false;
  const stored = await storage.get(`${prefix}${seqToId(anchor.seq)}`);
  if (stored === null) return lastSeq > anchor.seq;
  try {
    return signingInputHash(decodeDashboardLogEntry(stored)) === anchor.hash;
  } catch {
    return false;
  }
}

/**
 * アンカーを前進させてよい状態か（追記・削除の**前**に呼ぶ）。アンカー未導入は前進可（現在の末尾を採用）、
 * 壊れている / 末尾が食い違っている場合は不可（巻き戻しを追認しない）。
 */
export async function tailAnchorMayAdvance(
  storage: DashboardLogStorage,
  prefix: string,
  sortedKeys: readonly string[],
): Promise<boolean> {
  const stored = await readTailAnchor(storage, prefix);
  if (stored.kind === 'absent') return true;
  return stored.kind === 'present' && (await tailHolds(storage, prefix, sortedKeys, stored.anchor));
}

/**
 * 削除操作 `op`（Art.17）の前後でアンカーを追従させる。削除は末尾エントリを正当に消し得るため、事後に
 * 残存末尾へアンカーを移す（整合していたときだけ。巻き戻し済みのアンカーは据え置く）。全件消えたら
 * アンカーごと破棄する（`purge()` による全消去は巻き戻し状態からの回復手段でもある）。
 *
 * 呼び出し側が追記と同じロックで包むこと（追記との競合でアンカーが古い末尾へ戻るのを防ぐ）。
 */
export async function withTailAnchorFollowing<T>(
  storage: DashboardLogStorage,
  prefix: string,
  op: () => Promise<T>,
): Promise<T> {
  const advance = await tailAnchorMayAdvance(storage, prefix, (await storage.list(prefix)).sort());
  const result = await op();
  const keys = (await storage.list(prefix)).sort();
  const lastKey = keys[keys.length - 1];
  if (lastKey === undefined) {
    await storage.delete(tailAnchorKeyFor(prefix));
  } else if (advance) {
    const stored = await storage.get(lastKey);
    if (stored !== null) {
      try {
        await writeTailAnchor(storage, prefix, decodeDashboardLogEntry(stored));
      } catch {
        // 末尾エントリが復号できない（破損）。アンカーは据え置き、`verify` の `undecodable` に委ねる。
      }
    }
  }
  return result;
}
