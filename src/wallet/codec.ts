/**
 * Wallet ファサードで DID Document を符号化・復号するヘルパ。
 *
 * DID Document を storage 永続化用のバイト列（UTF-8 JSON）へ相互変換する。ファサードの
 * 永続化処理から符号化の関心事を分離したモジュールで、internal 用途（`index.ts` からは
 * re-export しない）。
 *
 * ストレージからの読み出し時のエラー処理:
 * - decode 失敗（storage 上のデータ破損）は入力由来のため、message / cause に元データを載せず
 *   `VericertsError(2001)` に正規化する。
 */

import { ErrorCodes, VericertsError } from '../internal/errors.js';
import type { DIDDocument } from '../internal/identity/did.js';
import { parseJsonWithoutPrototype } from '../internal/prototype-safety/parse-json.js';

/**
 * DID Document を storage 保存用のバイト列（UTF-8 JSON）へ符号化する。
 *
 * @param document 符号化する DID Document。
 * @returns UTF-8 エンコードされた JSON バイト列。
 */
export function encodeDocument(document: DIDDocument): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(document));
}

/**
 * storage から取得したバイト列（UTF-8 JSON）を DID Document へ復号する。
 *
 * storage 上のデータが破損し parse に失敗した場合は、ファサードの不変条件に従い
 * VericertsError(2001) に正規化する（破損＝入力由来のため message / cause には載せない）。
 *
 * @param bytes `encodeDocument` が生成したバイト列。
 * @returns 復号された DID Document。
 * @throws 破損で parse 失敗（VericertsError、code `2001`）。
 */
export function decodeDocument(bytes: Uint8Array): DIDDocument {
  try {
    return parseJsonWithoutPrototype(new TextDecoder().decode(bytes)) as DIDDocument;
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}
