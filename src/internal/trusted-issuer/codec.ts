/**
 * TrustedIssuerList の storage 符号化ヘルパ（gdpr/codec.ts / persona/codec.ts パターン）。
 *
 * `TrustedIssuerList` を storage 永続化用のバイト列（UTF-8 JSON）へ相互変換する。
 *
 * セキュリティ上の注意:
 * - decode 失敗（storage 上のデータ破損）は入力由来のため、message / cause に元データを載せず
 *   `VericertsError(STORAGE_RECORD_CORRUPTED)`（code `6005`）に正規化する。TrustedIssuerList は VC
 *   ではないため VC 専用コード（`VC_NOT_FOUND`）は流用しない（gdpr/codec.ts と同じ判断）。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import type { TrustedIssuerEntry, TrustedIssuerList } from './types.js';

/**
 * TrustedIssuerList を storage 保存用のバイト列（UTF-8 JSON）へ符号化する。
 *
 * @param list 符号化するリスト。
 * @returns UTF-8 エンコードされた JSON バイト列。
 */
export function encodeTrustedIssuerList(list: TrustedIssuerList): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(list));
}

/**
 * storage から取得したバイト列を TrustedIssuerList へ復号する。
 *
 * @param bytes `encodeTrustedIssuerList` が生成したバイト列。
 * @returns 復号されたリスト。
 * @throws 破損で parse / 最小構造検証に失敗（VericertsError、`STORAGE_RECORD_CORRUPTED` = code `6005`）。
 */
export function decodeTrustedIssuerList(bytes: Uint8Array): TrustedIssuerList {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(bytes));
  } catch {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  if (!isTrustedIssuerList(parsed)) {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  return parsed;
}

/** 復号した値が `TrustedIssuerEntry` の必須フィールドを満たすかを検証する型ガード。 */
function isTrustedIssuerEntry(value: unknown): value is TrustedIssuerEntry {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return typeof v.id === 'string' && typeof v.name === 'string';
}

/**
 * 復号した値が `TrustedIssuerList` の必須フィールドを満たすかを検証する型ガード。
 *
 * `trustedIssuers` は配列であり、各要素が `TrustedIssuerEntry` の最小形（`id` / `name`）を
 * 満たすことまで確認する（任意フィールドの型までは検査しない）。
 */
function isTrustedIssuerList(value: unknown): value is TrustedIssuerList {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === 'string' &&
    v.type === 'TrustedIssuerList' &&
    v.version === 'TSLv1' &&
    typeof v.listOperator === 'string' &&
    typeof v.listName === 'string' &&
    typeof v.issuedAt === 'string' &&
    Array.isArray(v.trustedIssuers) &&
    v.trustedIssuers.every(isTrustedIssuerEntry)
  );
}
