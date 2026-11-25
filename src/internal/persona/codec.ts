/**
 * persona メタデータの storage 符号化ヘルパ。
 *
 * `PersonaMetadata` を storage 永続化用のバイト列（UTF-8 JSON）へ相互変換する。wallet/codec.ts と
 * 同様に internal 用途で、永続化の関心事をマネージャ本体から分離する。
 *
 * セキュリティ上の注意:
 * - decode 失敗（storage 上のデータ破損）は入力由来のため、message / cause に元データを載せず
 *   `VericertsError(2005)` に正規化する。メタデータに秘密は含まれないが、念のため破損内容も載せない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import {
  PERSONA_DID_METHODS,
  PERSONA_KEY_SOURCES,
  PERSONA_KEY_TYPES,
  PERSONA_RELATIONSHIPS,
  type PersonaMetadata,
} from './types.js';

/**
 * ペルソナメタデータを storage 保存用のバイト列（UTF-8 JSON）へ符号化する。
 *
 * @param metadata 符号化するメタデータ。
 * @returns UTF-8 エンコードされた JSON バイト列。
 */
export function encodeMetadata(metadata: PersonaMetadata): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(metadata));
}

/**
 * storage から取得したバイト列（UTF-8 JSON）をペルソナメタデータへ復号する。
 *
 * storage 上のデータが破損し parse に失敗、または最小限の構造検証に失敗した場合は
 * `VericertsError(2005)` に正規化する（破損＝入力由来のため message / cause には載せない）。
 *
 * @param bytes `encodeMetadata` が生成したバイト列。
 * @returns 復号されたメタデータ。
 * @throws 破損で parse / 検証に失敗（VericertsError、code `2005`）。
 */
export function decodeMetadata(bytes: Uint8Array): PersonaMetadata {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(bytes));
  } catch {
    throw new VericertsError(ErrorCodes.PERSONA_NOT_FOUND);
  }
  if (!isPersonaMetadata(parsed)) {
    throw new VericertsError(ErrorCodes.PERSONA_NOT_FOUND);
  }
  return parsed;
}

/**
 * 復号した値が `PersonaMetadata` の必須フィールドを満たすかを検証する型ガード。
 *
 * 任意の `label` も存在する場合は文字列であることを確認する。後から追加した任意項目（`address` /
 * `method` / `keyType` / `keySource` / `kid` / `relationships`）は**欠落なら旧レコードとして受理**し
 * （移行不要・後方互換）、存在するなら型・既知の値であることを確認する。秘密は含めない型のため値の中身までは
 * 検査せず、型のみを確認する。
 *
 * `label` の型検証が必要な理由: 本 decode はパース境界
 * （`parseJsonWithoutPrototype`）を通るため、storage 上のオブジェクト値は `Object.prototype` を
 * 継承せず `toString` / `valueOf` を持たない。型不正な `label` が
 * `listPersonas({ sortBy: 'label' })` の `String#localeCompare` の引数に届くと、引数の暗黙
 * `ToString` が `TypeError: No default value` を送出し、破損レコードに対する文書化された失敗
 * （2005）ではなく生の例外が漏れる。
 *
 * @param value 検証対象（JSON.parse の結果）。
 * @returns 必須フィールドが揃っていれば true。
 */
function isPersonaMetadata(value: unknown): value is PersonaMetadata {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === 'string' &&
    typeof v.index === 'number' &&
    typeof v.did === 'string' &&
    (v.address === undefined || typeof v.address === 'string') &&
    typeof v.derivationPath === 'string' &&
    typeof v.createdAt === 'number' &&
    typeof v.lastUsedAt === 'number' &&
    (v.label === undefined || typeof v.label === 'string') &&
    isOptionalMember(v.method, PERSONA_DID_METHODS) &&
    isOptionalMember(v.keyType, PERSONA_KEY_TYPES) &&
    isOptionalMember(v.keySource, PERSONA_KEY_SOURCES) &&
    (v.kid === undefined || typeof v.kid === 'string') &&
    (v.relationships === undefined ||
      (Array.isArray(v.relationships) &&
        v.relationships.every((entry) => PERSONA_RELATIONSHIPS.includes(entry))))
  );
}

/** 後から追加した任意項目（`method` / `keyType` / `keySource`）が、欠落か既知の値であるか。旧レコードは欠落で通る。 */
function isOptionalMember(value: unknown, allowed: readonly string[]): boolean {
  return value === undefined || (typeof value === 'string' && allowed.includes(value));
}
