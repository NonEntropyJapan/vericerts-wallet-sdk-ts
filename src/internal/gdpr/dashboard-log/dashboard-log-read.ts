/**
 * `DashboardLog` の厳格な読み出し（破損は例外）。`dashboard-log.ts` の行数を抑えるため切り出した。
 * 破損を許容する検証用の読み出しは `log-integrity/verify-stored.ts` が別に持つ。
 */

import { decodeDashboardLogEntry } from '../codec.js';
import type { DashboardLogEntry } from '../types.js';
import { type DashboardLogStorage, signingInputHash } from './dashboard-log-shared.js';

/**
 * 指定パーティションのエントリを追記順（連番昇順）で返す。
 *
 * Storage.list の順序は実装依存（インターフェース契約は順序未規定）。連番はゼロ埋めのため、
 * キーを辞書順ソートすれば追記順＝ chain 順に一致する（バックエンドの順序に依存しない）。
 *
 * @throws storage 上のデータ破損で復号に失敗した場合（VericertsError、code `6005`）。
 */
export async function listPartition(
  storage: DashboardLogStorage,
  prefix: string,
): Promise<DashboardLogEntry[]> {
  const keys = (await storage.list(prefix)).sort();
  const entries: DashboardLogEntry[] = [];
  for (const key of keys) {
    const stored = await storage.get(key);
    if (stored !== null) {
      entries.push(decodeDashboardLogEntry(stored));
    }
  }
  return entries;
}

/**
 * 直前（末尾）エントリの signing-input の SHA-256（base64url）を返す。
 *
 * `signature`（`header.payload.signature`）の先頭 2 セグメント（signing-input）をハッシュ対象とする。
 *
 * @param keys 既存エントリの storage キー（辞書順ソート済み・1 件以上。呼び出し側が保証する）。
 * @throws 末尾エントリの読み出し・復号に失敗した場合（VericertsError、code `6005`）。
 */
export async function lastSigningInputHash(
  storage: DashboardLogStorage,
  keys: readonly string[],
): Promise<string> {
  const stored = await storage.get(keys[keys.length - 1] as string);
  return signingInputHash(decodeDashboardLogEntry(stored as Uint8Array));
}
