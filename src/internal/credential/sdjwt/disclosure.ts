/**
 * SD-JWT の Disclosure（開示）プリミティブ。
 *
 * RFC 9901 準拠。各 Disclosure は JSON 配列を `base64url` でエンコードし、その SHA-256 digest を
 * Issuer-signed JWT の `_sd` 配列（オブジェクトプロパティ用）または `{"...": digest}`（配列要素用）に
 * 格納する（`sdjwt.ts`）。形式は 2 種類ある（§4.2.1 / §4.2.2）:
 * - オブジェクトプロパティ: `[salt, claim_name, claim_value]`（3 要素）
 * - 配列要素: `[salt, element_value]`（2 要素。`claimName` は無い）
 *
 * 本モジュールは Disclosure 単体の生成（`encodeDisclosure`）・digest 計算（`disclosureDigest`）・
 * 分解（`decodeDisclosure`）のみを担う。入れ子の復元は `claims.ts` の `recoverClaims`。
 *
 * `jose` 等の JWT / SD-JWT ライブラリは導入せず、`@noble/hashes` の sha256 と `@scure/base` の
 * base64urlnopad のみを使う。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に salt・開示値を含めない。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';

/**
 * デコード済み Disclosure。
 *
 * オブジェクトプロパティ用（3 要素 `[salt, name, value]`）は `claimName` を持ち、配列要素用
 * （2 要素 `[salt, value]`）は `claimName` を持たない（RFC 9901 §4.2.2）。
 */
export interface Disclosure {
  /** ランダムな salt（base64url 文字列）。 */
  readonly salt: string;
  /** 開示するクレーム名。配列要素の Disclosure（2 要素）では `undefined`。 */
  readonly claimName?: string;
  /** 開示するクレーム値（任意の JSON 値）。配列要素の Disclosure ではその要素の値。 */
  readonly value: unknown;
  /** この Disclosure の base64url エンコード文字列（`~` 区切りで連結される実体）。 */
  readonly encoded: string;
  /** `encoded` の SHA-256 digest（base64url、`_sd` 配列に格納される値）。 */
  readonly digest: string;
}

/** オブジェクトプロパティの Disclosure に使えない予約クレーム名（RFC 9901 §4.2.1）。 */
const RESERVED_CLAIM_NAMES: ReadonlySet<string> = new Set(['_sd', '...']);

/** salt のバイト長（draft 推奨の 128bit 以上を満たす 16 バイト）。 */
const SALT_BYTES = 16;

/**
 * Disclosure 文字列の SHA-256 digest（base64url）を計算する。
 *
 * digest は Disclosure の **ASCII バイト列**（base64url 文字列そのもの）に対して取る
 * （draft の `_sd` 値の規定）。
 *
 * @param encoded Disclosure の base64url エンコード文字列。
 * @returns SHA-256 digest（base64url、パディングなし）。
 */
export function disclosureDigest(encoded: string): string {
  return base64urlnopad.encode(sha256(new TextEncoder().encode(encoded)));
}

/**
 * salt・claim 名・値から Disclosure を生成する。
 *
 * `[salt, claimName, value]` の JSON 配列を UTF-8 → base64url エンコードし、その digest を計算する。
 * salt 未指定時は暗号学的乱数（`crypto.getRandomValues`）で 16 バイト生成する。
 *
 * @param claimName 開示するクレーム名。
 * @param value 開示するクレーム値。
 * @param salt salt（テストの決定性のため注入可能。未指定時はランダム生成）。
 * @returns 生成した `Disclosure`。
 */
export function encodeDisclosure(claimName: string, value: unknown, salt?: string): Disclosure {
  const resolvedSalt =
    salt ?? base64urlnopad.encode(crypto.getRandomValues(new Uint8Array(SALT_BYTES)));
  const encoded = base64urlnopad.encode(
    new TextEncoder().encode(JSON.stringify([resolvedSalt, claimName, value])),
  );
  return {
    salt: resolvedSalt,
    claimName,
    value,
    encoded,
    digest: disclosureDigest(encoded),
  };
}

/**
 * Disclosure の base64url 文字列をデコードして構成要素へ分解する。
 *
 * `[salt, claimName, value]`（オブジェクトプロパティ、3 要素）または `[salt, value]`（配列要素、
 * 2 要素）の JSON 配列であることを検証する（RFC 9901 §4.2.1 / §4.2.2）。要素数不正・JSON 不正・
 * salt / claimName が文字列でない場合は構造不正に正規化する（開示値は message に含めない）。
 * オブジェクトプロパティの `claimName` が `_sd` / `...` の場合も拒否する（§4.2.1。`_sd` は
 * ダイジェスト配列、`...` は配列要素の参照に予約されており、digest 照合を壊すため）。
 *
 * @param encoded Disclosure の base64url 文字列。
 * @returns デコード済み `Disclosure`。
 * @throws base64url / JSON / 配列形状が不正、または予約名の `claimName` の場合（VericertsError、code `3010`）。
 */
export function decodeDisclosure(encoded: string): Disclosure {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(new TextDecoder().decode(base64urlnopad.decode(encoded)));
  } catch {
    // base64url / JSON 由来例外は cause を渡さず正規化する（入力値を漏らさない）。
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  if (!Array.isArray(parsed) || (parsed.length !== 2 && parsed.length !== 3)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  const digest = disclosureDigest(encoded);
  if (parsed.length === 2) {
    const [salt, value] = parsed;
    if (typeof salt !== 'string') {
      throw new VericertsError(ErrorCodes.SIG_INVALID);
    }
    return { salt, value, encoded, digest };
  }
  const [salt, claimName, value] = parsed;
  if (typeof salt !== 'string' || typeof claimName !== 'string') {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  if (RESERVED_CLAIM_NAMES.has(claimName)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  return { salt, claimName, value, encoded, digest };
}
