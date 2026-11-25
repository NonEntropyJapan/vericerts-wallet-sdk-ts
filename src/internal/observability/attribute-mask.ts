/**
 * ログ属性の PII マスキング。キー名と値の構造に基づくルールを適用する。
 *
 * `logger.ts`（注入ロガーへ渡す直前の強制マスク）と `warning.ts`（`onWarning` へ渡す失敗の中身）が
 * 同じ規則を共有するための切り出し。`logger.ts` は `DEBUG` 名前空間の判定で `process` を読むため、
 * マスクだけを使いたい側（拡張の型検査など `process` の型が無い環境）が `logger.ts` を巻き込まないようにする。
 * 値そのものの構造検出（JWT / SD-JWT / COSE）は `pii-mask.ts` に分けてある。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { maskStructuredValue, REDACTED } from './pii-mask.js';

/** ログ属性に載せられる値。 */
export type LogValue = string | number | boolean | null | LogValue[] | { [k: string]: LogValue };

/** 構造化ログの属性。 */
export type LogAttributes = Record<string, LogValue>;

/**
 * キー名を判定用に正規化する（小文字化し、英数字以外を除く）。
 *
 * `private_key` / `private-key` / `Private Key` を `privatekey` に揃え、命名規約（snake_case /
 * kebab-case / camelCase）の違いで強制マスクをすり抜けさせない。
 */
function normalizeKeyName(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** キー名に含まれていたらキーごと落とす（`*mnemonic*` / `*privateKey*` / `*pin*`）。 */
const DROP_KEY_SUBSTRINGS = ['mnemonic', 'privatekey', 'pin'] as const;

/** キー名に含まれていたら値を `[REDACTED]` にする（`*.credentialSubject.*`）。 */
const REDACT_KEY_SUBSTRINGS = ['credentialsubject'] as const;

/**
 * キー名が一致したら値を `[REDACTED]` にする（`*.portrait` / `*.document_number`）。
 * 比較は `normalizeKeyName` 後の形で行うため `documentnumber` と綴る。
 */
const REDACT_KEY_NAMES = ['portrait', 'documentnumber'] as const;

/** キー名が一致したら値をハッシュ化する（`email` / `phone` / `address` / `ssn`）。 */
const HASH_KEY_NAMES = ['email', 'phone', 'address', 'ssn'] as const;

/** 属性値を SHA-256 でハッシュ化して残す先頭の桁数。 */
const HASH_PREFIX_LENGTH = 8;

/** 値を `sha256` hex の先頭 8 桁に潰す（元の値は復元できないが同一性の追跡には使える）。 */
function hashValue(value: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(value))).slice(0, HASH_PREFIX_LENGTH);
}

/** ネストした値を再帰的にマスクする（配列・オブジェクトの中の PII も対象）。 */
function maskValue(value: LogValue): LogValue {
  if (Array.isArray(value)) {
    return value.map(maskValue);
  }
  if (typeof value === 'object' && value !== null) {
    return maskLogAttributes(value);
  }
  if (typeof value === 'string') {
    return maskStructuredValue(value);
  }
  return value;
}

/**
 * ログ属性へ PII マスキングを適用した**新しい**オブジェクトを返す。
 *
 * キー名による判定の順序は「削除 → `[REDACTED]` → ハッシュ化 → 値の検査（再帰）」。
 * 先に削除を見るのは、`mnemonic` 等が他の規則にも当たった場合に**残ってしまう方**へ倒さない
 * ためである。キーの列挙は own かつ列挙可能なものに限る（`Object.entries`）。
 *
 * どのキー規則にも当たらなかった値は `maskStructuredValue` が受け取り、JWT / SD-JWT / COSE
 * の構造を検出した場合は payload を落とす。
 */
export function maskLogAttributes(attrs: LogAttributes): LogAttributes {
  const masked: LogAttributes = {};
  for (const [key, value] of Object.entries(attrs)) {
    const name = normalizeKeyName(key);
    if (DROP_KEY_SUBSTRINGS.some((pattern) => name.includes(pattern))) {
      continue;
    }
    if (
      REDACT_KEY_SUBSTRINGS.some((pattern) => name.includes(pattern)) ||
      REDACT_KEY_NAMES.some((redacted) => name === redacted)
    ) {
      masked[key] = REDACTED;
      continue;
    }
    if (HASH_KEY_NAMES.some((hashed) => name === hashed)) {
      masked[key] = typeof value === 'string' ? hashValue(value) : REDACTED;
      continue;
    }
    masked[key] = maskValue(value);
  }
  return masked;
}
