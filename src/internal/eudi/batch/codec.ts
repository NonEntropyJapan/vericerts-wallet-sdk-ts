/**
 * BatchCredentialPool の storage 符号化ヘルパ（`delegated-did/codec.ts` / `trusted-issuer/codec.ts`
 * と同パターン）。
 *
 * `BatchCredentialPool` を storage 永続化用のバイト列（UTF-8 JSON）へ相互変換する。
 *
 * セキュリティ上の注意:
 * - decode 失敗（storage 上のデータ破損）は入力由来のため、message / cause に元データを載せず
 *   `VericertsError(STORAGE_RECORD_CORRUPTED)`（code `6005`）に正規化する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { BatchCredentialPool } from './types.js';

/**
 * BatchCredentialPool を storage 保存用のバイト列（UTF-8 JSON）へ符号化する。
 *
 * @param pool 符号化するプール。
 * @returns UTF-8 エンコードされた JSON バイト列。
 */
export function encodeBatchCredentialPool(pool: BatchCredentialPool): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(pool));
}

/**
 * storage から取得したバイト列を BatchCredentialPool へ復号する。
 *
 * @param bytes `encodeBatchCredentialPool` が生成したバイト列。
 * @returns 復号されたプール。
 * @throws 破損で parse / 最小構造検証に失敗（VericertsError、`STORAGE_RECORD_CORRUPTED` = code `6005`）。
 */
export function decodeBatchCredentialPool(bytes: Uint8Array): BatchCredentialPool {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(bytes));
  } catch {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  if (!isBatchCredentialPool(parsed)) {
    throw new VericertsError(ErrorCodes.STORAGE_RECORD_CORRUPTED);
  }
  return parsed;
}

/** 復号した値が `BatchCredentialPool` の必須フィールドを満たすかを検証する型ガード。 */
function isBatchCredentialPool(value: unknown): value is BatchCredentialPool {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === 'string' &&
    typeof v.vct === 'string' &&
    typeof v.issuerDID === 'string' &&
    typeof v.totalCount === 'number' &&
    typeof v.usedCount === 'number' &&
    typeof v.threshold === 'number' &&
    typeof v.createdAt === 'number' &&
    typeof v.refreshedAt === 'number'
  );
}
