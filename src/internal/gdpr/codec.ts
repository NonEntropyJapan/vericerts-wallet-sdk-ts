/**
 * GDPR モジュールのレコード storage 符号化ヘルパ（persona/codec.ts パターン）。
 *
 * `CredentialRecord` / `DashboardLogEntry` を storage 永続化用のバイト列（UTF-8 JSON）へ相互変換する。
 * 永続化の関心事を store / log 本体から分離する。
 *
 * セキュリティ上の注意:
 * - decode 失敗（storage 上のデータ破損）は入力由来のため、message / cause に元データを載せず
 *   `VericertsError` に正規化する。VC レコードに秘密は含まれないが、念のため破損内容も載せない。
 * - 正規化先のコードはレコード種別で分ける:
 *   - `CredentialRecord`（VC 本体のレコード）: `VC_NOT_FOUND`（code `3070`）。破損した VC レコードは
 *     「見つからない」のと同義に扱い、VC 系エラーカテゴリに揃える。
 *   - `DashboardLogEntry`（GDPR 監査ログのレコード。VC ではない）: `STORAGE_RECORD_CORRUPTED`
 *     （code `6005`）。VC 専用コードを流用せず storage カテゴリの専用コードを使う。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { ownProperty } from '../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import type { CredentialRecord, DashboardLogEntry, PresentedToEntry } from './types.js';

/**
 * CredentialRecord を storage 保存用のバイト列（UTF-8 JSON）へ符号化する。
 *
 * @param record 符号化するレコード。
 * @returns UTF-8 エンコードされた JSON バイト列。
 */
export function encodeCredentialRecord(record: CredentialRecord): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(record));
}

/**
 * storage から取得したバイト列を CredentialRecord へ復号する。
 *
 * storage 上のデータが破損し parse / 最小構造検証に失敗した場合は `VericertsError(VC_NOT_FOUND)`
 * （code `3070`）に正規化する（破損＝入力由来のため message / cause には載せない）。破損した VC
 * レコードは「見つからない」のと同義に扱い、VC 系エラーカテゴリ（`VC_NOT_FOUND`）に揃える。
 *
 * @param bytes `encodeCredentialRecord` が生成したバイト列。
 * @returns 復号されたレコード。
 * @throws 破損で parse / 検証に失敗（VericertsError、`VC_NOT_FOUND` = code `3070`）。
 */
export function decodeCredentialRecord(bytes: Uint8Array): CredentialRecord {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(bytes));
  } catch {
    throw new VericertsError(ErrorCodes.VC_NOT_FOUND);
  }
  if (!isCredentialRecord(parsed)) {
    throw new VericertsError(ErrorCodes.VC_NOT_FOUND);
  }
  return parsed;
}

/**
 * DashboardLogEntry を storage 保存用のバイト列（UTF-8 JSON）へ符号化する。
 *
 * @param entry 符号化するエントリ。
 * @returns UTF-8 エンコードされた JSON バイト列。
 */
export function encodeDashboardLogEntry(entry: DashboardLogEntry): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(entry));
}

/**
 * storage から取得したバイト列を DashboardLogEntry へ復号する。
 *
 * 破損時は `VericertsError(STORAGE_RECORD_CORRUPTED)`（code `6005`）に正規化する。`DashboardLogEntry`
 * は GDPR 監査ログのレコードであり VC ではないため、VC 専用の `VC_NOT_FOUND`(3070) は流用せず
 * storage カテゴリの専用コードを使う。
 *
 * @param bytes `encodeDashboardLogEntry` が生成したバイト列。
 * @returns 復号されたエントリ。
 * @throws 破損で parse / 検証に失敗（VericertsError、`STORAGE_RECORD_CORRUPTED` = code `6005`）。
 */
export function decodeDashboardLogEntry(bytes: Uint8Array): DashboardLogEntry {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(bytes));
  } catch {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  if (!isDashboardLogEntry(parsed)) {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  return parsed;
}

/**
 * 復号した値が `CredentialRecord` の必須フィールドを満たすかを検証する型ガード。
 *
 * `disputed` / `disputeReason` / `disputedAt` は任意のため検証しない。VC 本体（`credential`）は
 * object であることのみ確認する（詳細な VC 構造検証は credential モジュールの責務）。
 *
 * @param value 検証対象（JSON.parse の結果）。
 * @returns 必須フィールドが揃っていれば true。
 */
function isCredentialRecord(value: unknown): value is CredentialRecord {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === 'string' &&
    typeof v.receivedAt === 'string' &&
    typeof v.credential === 'object' &&
    v.credential !== null
  );
}

/**
 * 復号した値が `DashboardLogEntry` の必須フィールドを満たすかを検証する型ガード。
 *
 * @param value 検証対象（JSON.parse の結果）。
 * @returns 必須フィールドが揃っていれば true。
 */
function isDashboardLogEntry(value: unknown): value is DashboardLogEntry {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === 'string' &&
    typeof v.type === 'string' &&
    typeof v.recordedAt === 'string' &&
    typeof v.payload === 'object' &&
    v.payload !== null &&
    (v.prevHash === null || typeof v.prevHash === 'string') &&
    typeof v.signature === 'string'
  );
}

/**
 * `record.presentedTo` に提示履歴を 1 件追記した新しいレコードを返す。既存の履歴は own 限定で読む
 * （省略した `presentedTo` が `Object.prototype` の汚染値を拾って履歴に混入しない）。
 */
export function withPresentedTo(
  record: CredentialRecord,
  entry: PresentedToEntry,
): CredentialRecord {
  const history = ownProperty<readonly PresentedToEntry[]>(record, 'presentedTo') ?? [];
  return { ...record, presentedTo: [...history, entry] };
}
