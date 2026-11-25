/**
 * contentHash 表記（`<alg>-<digest>` / multibase multihash）のパースと正規化。
 *
 * 受理する表記:
 * - `<alg>-<hex>` — Artifact DID のサブパス例 `sha256-ab12…`
 * - `<alg>-<base64url>` — padding あり / なしのどちらも可
 * - `<alg>-<multibase>` — ダイジェスト部が multibase 文字列
 * - `<multibase multihash>` — アルゴリズム名を持たず、multihash コードから判定する
 *
 * canonical 表記は `<canonical alg>-<小文字 hex>`（例 `sha2-256-ab12…`）とする。
 * アルゴリズム名は multicodec のハッシュ関数名に正規化する。
 *
 * セキュリティ上の注意:
 * - 未対応アルゴリズム・不正表記は fail-closed で例外にする。既定アルゴリズムへの
 *   フォールバックは行わない（未対応ハッシュを「検証済み」に見せないため）。
 * - 例外メッセージや `context` に入力文字列を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  ALGORITHM_ALIAS_NAMES,
  type ContentHashAlgorithm,
  findAlgorithmSpecByMultihashCode,
  getAlgorithmSpec,
  hasKnownUnsupportedAlgorithmPrefix,
  normalizeAlgorithmName,
} from './algorithms.js';
import {
  decodeDigest,
  decodeMultibase,
  encodeHex,
  MAX_CONTENT_HASH_TEXT_LENGTH,
} from './digest-codec.js';
import { decodeMultihash } from './multihash.js';

/** 正規化済みの contentHash。 */
export interface ParsedContentHash {
  /** アルゴリズムの canonical 名（multicodec のハッシュ関数名）。 */
  readonly algorithm: ContentHashAlgorithm;
  /** ダイジェスト本体。 */
  readonly digest: Uint8Array;
  /** canonical 表記 `<algorithm>-<小文字 hex>`。 */
  readonly notation: string;
}

/**
 * アルゴリズムとダイジェストから canonical 表記を組み立てる。
 *
 * @param algorithm canonical 名。
 * @param digest ダイジェスト本体。
 * @returns `<algorithm>-<小文字 hex>`。
 */
export function formatContentHash(algorithm: ContentHashAlgorithm, digest: Uint8Array): string {
  return `${algorithm}-${encodeHex(digest)}`;
}

/** `<alg>-` プレフィックスを最長一致で切り出す。 */
function splitAlgorithmPrefix(
  text: string,
): { algorithm: ContentHashAlgorithm; rest: string } | undefined {
  const lowered = text.toLowerCase();
  // alias は長い順に並んでいる。`sha2-256` と `sha-256` のように一方が他方の断片に
  // 見えるケースがあるため、必ず最長一致を採用する。
  for (const alias of ALGORITHM_ALIAS_NAMES) {
    if (!lowered.startsWith(`${alias}-`)) {
      continue;
    }
    const algorithm = normalizeAlgorithmName(alias);
    if (algorithm === undefined) {
      continue;
    }
    return { algorithm, rest: text.slice(alias.length + 1) };
  }
  return undefined;
}

/**
 * multibase multihash 表記（アルゴリズム名なし）のパースを試みる。
 *
 * multibase / multihash として解釈できない場合は `undefined` を返す（呼び出し側で
 * 「未対応アルゴリズム名付きの表記」と区別してエラーコードを決める）。デコードは
 * できたが multihash コードが未対応の場合だけは、ここで fail-closed に例外化する。
 *
 * @param text multibase 文字列。
 * @returns 正規化済み contentHash。multibase multihash として解釈できないなら `undefined`。
 * @throws multihash コードが未対応の場合（VericertsError、code `1030`）。
 */
function tryParseMultibaseMultihash(text: string): ParsedContentHash | undefined {
  const bytes = decodeMultibase(text);
  if (bytes === undefined) {
    return undefined;
  }
  const multihash = decodeMultihash(bytes);
  if (multihash === undefined) {
    return undefined;
  }
  const spec = findAlgorithmSpecByMultihashCode(multihash.code);
  if (spec === undefined) {
    throw new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM);
  }
  if (multihash.digest.length !== spec.digestLength) {
    throw new VericertsError(ErrorCodes.CONTENT_HASH_FORMAT_INVALID);
  }
  // subarray はデコード結果のバッファを共有するためコピーして切り離す。
  const digest = Uint8Array.from(multihash.digest);
  return { algorithm: spec.algorithm, digest, notation: formatContentHash(spec.algorithm, digest) };
}

/**
 * contentHash 表記をパースして正規化する。
 *
 * @param text DID サブパス / VC claim に現れた contentHash 表記。
 * @returns 正規化済み contentHash。
 * @throws 表記不正の場合（VericertsError、code `2016`）。
 * @throws 未対応アルゴリズムの場合（VericertsError、code `1030`）。
 */
export function parseContentHash(text: string): ParsedContentHash {
  // 署名検証前の攻撃者制御入力。base58 デコード・`-` 走査の二次時間を避けるため入口で長さを打ち切る。
  if (typeof text !== 'string' || text.length === 0 || text.length > MAX_CONTENT_HASH_TEXT_LENGTH) {
    throw new VericertsError(ErrorCodes.CONTENT_HASH_FORMAT_INVALID);
  }
  const split = splitAlgorithmPrefix(text);
  if (split !== undefined) {
    const spec = getAlgorithmSpec(split.algorithm);
    const digest = decodeDigest(split.rest, spec.digestLength);
    if (digest === undefined) {
      throw new VericertsError(ErrorCodes.CONTENT_HASH_FORMAT_INVALID);
    }
    return {
      algorithm: spec.algorithm,
      digest,
      notation: formatContentHash(spec.algorithm, digest),
    };
  }
  // `<対応 alg>-` を持たない表記は multibase multihash として解釈を試みる。
  const parsed = tryParseMultibaseMultihash(text);
  if (parsed !== undefined) {
    return parsed;
  }
  // 既知だが未対応のアルゴリズム名付き（例 `md5-…` / `sha3-512-…`）だけを 1030 とし、
  // それ以外（`docs:v1-2` のような content-addressed でないサブパスを含む）は 2016 とする。
  throw new VericertsError(
    hasKnownUnsupportedAlgorithmPrefix(text)
      ? ErrorCodes.UNSUPPORTED_ALGORITHM
      : ErrorCodes.CONTENT_HASH_FORMAT_INVALID,
  );
}
