/**
 * DelegatedDID の storage 符号化ヘルパ（gdpr/codec.ts / trusted-issuer/codec.ts パターン）。
 *
 * `DelegatedDID` を storage 永続化用のバイト列（UTF-8 JSON）へ相互変換する。
 *
 * セキュリティ上の注意:
 * - decode 失敗（storage 上のデータ破損）は入力由来のため、message / cause に元データを載せず
 *   `VericertsError(STORAGE_RECORD_CORRUPTED)`（code `6005`）に正規化する。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import type { DelegatedDID, DelegationStatus } from './types.js';

/**
 * DelegatedDID を storage 保存用のバイト列（UTF-8 JSON）へ符号化する。
 *
 * @param record 符号化するレコード。
 * @returns UTF-8 エンコードされた JSON バイト列。
 */
export function encodeDelegatedDID(record: DelegatedDID): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(record));
}

/**
 * storage から取得したバイト列を DelegatedDID へ復号する。
 *
 * @param bytes `encodeDelegatedDID` が生成したバイト列。
 * @returns 復号されたレコード。
 * @throws 破損で parse / 最小構造検証に失敗（VericertsError、`STORAGE_RECORD_CORRUPTED` = code `6005`）。
 */
export function decodeDelegatedDID(bytes: Uint8Array): DelegatedDID {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(bytes));
  } catch {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  if (!isDelegatedDID(parsed)) {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  return parsed;
}

const DELEGATION_STATUSES: ReadonlySet<string> = new Set<DelegationStatus>([
  'active',
  'revoked',
  'unknown',
]);

/** 値が `DelegationStatus` の列挙値か。書き込み側（`DelegatedDIDStore`）と復号側で共有する。 */
export function isDelegationStatus(value: unknown): value is DelegationStatus {
  return typeof value === 'string' && DELEGATION_STATUSES.has(value);
}

/** 復号した値が `DelegatedDID` の必須フィールドを満たすかを検証する型ガード。 */
function isDelegatedDID(value: unknown): value is DelegatedDID {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.did === 'string' &&
    typeof v.controllerDID === 'string' &&
    typeof v.name === 'string' &&
    typeof v.resolvedAt === 'string' &&
    isDelegationStatus(v.status)
  );
}
