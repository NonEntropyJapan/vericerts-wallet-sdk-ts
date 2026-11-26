/**
 * Dashboard ログの永続化・エクスポート・インポートで共有する定数と純粋ヘルパ。
 *
 * `dashboard-log.ts`（追記・読み出し・削除・エクスポート／インポート）と `dashboard-log-import.ts`
 * （エクスポート検証）の双方が参照するため、循環 import を避けて独立モジュールに切り出す。ここには storage
 * 契約（`DashboardLogStorage`）・キー prefix・連番採番・signing-input ハッシュ計算など、責務横断の
 * 低レベル部品のみを置く（ドメインロジックは各モジュール側に残す）。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { emitWarning, type OnWarning } from '../../observability/warning.js';
import type { DashboardLogEntry } from '../types.js';

/**
 * storage 上でユーザー制御 Dashboard ログエントリを保存するキーの prefix。
 * `@vericerts/vericerts-wallet-sdk/gdpr` から公開する契約。値を変えると利用側の保存データ／出力と食い違う。
 */
export const DASHBOARD_LOG_KEY_PREFIX = 'dashboard-log/';

/**
 * storage 上で Art.17 削除監査記録を保存するキーの prefix。
 *
 * `dashboard-log/` とは独立したチェーンを持ち、`deleteCredential` / `purgeDashboardLog` の削除対象外とする
 * （削除の事実を監査用に残すため）。
 */
export const DELETION_LOG_KEY_PREFIX = 'deletion-log/';

/**
 * ユーザー制御 Dashboard ログの**末尾アンカー**（最終エントリの連番 + signing-input ハッシュ）を保存する
 * storage キー。`dashboard-log/` / `deletion-log/` のどちらの prefix にも一致させない（`list(prefix)` に
 * エントリとして混ざらない）。実体は `log-integrity/tail-anchor.ts`。
 * `@vericerts/vericerts-wallet-sdk/gdpr` から公開する契約。値を変えると利用側の保存データ／出力と食い違う。
 */
export const DASHBOARD_LOG_TAIL_ANCHOR_KEY = 'anchor/dashboard-log';

/**
 * パーティション prefix に対応する末尾アンカーの storage キー（`anchor/<prefix から末尾の / を除いたもの>`）。
 * `dashboard-log/` は {@link DASHBOARD_LOG_TAIL_ANCHOR_KEY}、Art.17 削除監査記録 `deletion-log/` は
 * `anchor/deletion-log`。どちらのキーも `list(prefix)` に混ざらない。
 */
export function tailAnchorKeyFor(prefix: string): string {
  return `anchor/${prefix.replace(/\/$/, '')}`;
}

/** エントリ ID の連番ゼロ埋め桁数（`list` の辞書順が追記順と一致するようにする）。 */
export const SEQ_PAD_WIDTH = 12;

/**
 * 永続化バックエンドへの最小依存。`Storage`（storage.ts）を構造的に満たす。
 *
 * 循環 import を避けるため `Storage` を直接 import せず、必要なメソッドのみを構造型として要求する
 * （`persona/persona.ts` の構造的 Storage 依存と同パターン）。
 */
export interface DashboardLogStorage {
  get(key: string): Promise<Uint8Array | null>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

/** 連番を storage キー用のゼロ埋め ID に変換する（辞書順＝追記順を保証）。 */
export function seqToId(seq: number): string {
  return String(seq).padStart(SEQ_PAD_WIDTH, '0');
}

/**
 * 既存キー群から次に採番すべき連番を返す（最大 seq + 1）。
 *
 * `keys.length` を連番に使うと、`purge` / `deleteEntriesForVc` で低番エントリのみ削除された後の追記が
 * 残存する高番エントリの ID と衝突し、`storage.set` で既存エントリを上書きする（監査ログ破壊・Merkle
 * chain 断絶）。件数ではなく既存 ID の最大 seq + 1 を採ることで、削除後も採番衝突を防ぐ。
 *
 * @param keys 同一パーティションの storage キー（`${prefix}${seqToId(seq)}` 形式）。順序不問。
 * @returns 空なら 0、非空なら（キー末尾のゼロ埋め連番）の最大値 + 1。
 */
export function nextSeq(keys: readonly string[]): number {
  let max = -1;
  for (const key of keys) {
    // キー末尾のゼロ埋め連番（`seqToId`）のみを解釈する。prefix を含む先頭部は無視する。
    const seq = Number.parseInt(key.slice(-SEQ_PAD_WIDTH), 10);
    if (Number.isFinite(seq) && seq > max) {
      max = seq;
    }
  }
  return max + 1;
}

/**
 * エントリの signing-input（`signature` 先頭 2 セグメント `header.payload`）の SHA-256（base64url）を返す。
 *
 * `prevHash` chain 連結（`append`）と export ルートハッシュ（`exportLog`）・import 検証で共有し、三者の
 * 一致を保証する。
 */
export function signingInputHash(entry: DashboardLogEntry): string {
  const signingInput = entry.signature.split('.').slice(0, 2).join('.');
  return base64urlnopad.encode(sha256(new TextEncoder().encode(signingInput)));
}

/**
 * 末尾アンカーの書込失敗を `onWarning` に流す。エントリは永続化済みで追記の結論は変わらないが、アンカーが
 * 遅れたまま気づかれないと巻き戻しの検知が弱くなる。気づきたい失敗なので流す（未指定なら何もしない）。
 */
export function warnTailAnchorFailed(onWarning: OnWarning | undefined, error: unknown): void {
  emitWarning(
    onWarning,
    {
      code: 'dashboard_log.tail_anchor_write_failed',
      message: 'Failed to write the dashboard log tail anchor; the entry itself was appended.',
      component: 'sdk.wallet',
    },
    error,
  );
}
