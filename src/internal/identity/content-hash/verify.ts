/**
 * contentHash の計算と照合。
 *
 * Verifier は、DID サブパスの hash を実コンテンツから計算した hash と照合する。
 * Provenance VC がある場合は、その `contentHash` claim と DID サブパスも照合する。
 * 不一致は `2009 CONTENT_HASH_MISMATCH` で識別できる。
 *
 * セキュリティ上の注意:
 * - ダイジェスト比較は必ず定数時間で行う（`internal/timing-safe.ts`）。`node:crypto` の
 *   `timingSafeEqual` は Node 専用 API であり、browser ターゲットのビルドでは使えない。
 * - アルゴリズムが食い違う場合も「一致しない」として fail-closed に拒否する。
 * - 例外メッセージや `context` に DID・ダイジェスト等の入力を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { timingSafeEqualBytes, timingSafeEqualString } from '../../timing-safe.js';
import { type ContentHashAlgorithm, getAlgorithmSpec } from './algorithms.js';
import { extractDidContentHash } from './did-subpath.js';
import { formatContentHash, type ParsedContentHash, parseContentHash } from './notation.js';

/** ハッシュ対象コンテンツ。大きな Artifact を全読みせずに済むよう stream も受ける。 */
export type ContentSource = Uint8Array | AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>;

/** `ReadableStream` かどうかを判定する（`Symbol.asyncIterator` 未実装の実装系にも対応）。 */
function isReadableStream(source: ContentSource): source is ReadableStream<Uint8Array> {
  return (
    typeof source === 'object' &&
    source !== null &&
    typeof (source as ReadableStream<Uint8Array>).getReader === 'function'
  );
}

/**
 * コンテンツからダイジェストを計算する。
 *
 * @param content バイト列・非同期イテラブル・`ReadableStream` のいずれか。
 * @param algorithm 使用するアルゴリズムの canonical 名（既定 `sha2-256`）。
 * @returns 正規化済み contentHash。
 * @throws 未対応アルゴリズムの場合（VericertsError、code `1030`）。
 */
export async function computeContentHash(
  content: ContentSource,
  algorithm: ContentHashAlgorithm = 'sha2-256',
): Promise<ParsedContentHash> {
  const spec = getAlgorithmSpec(algorithm);
  const hasher = spec.createHasher();
  if (content instanceof Uint8Array) {
    hasher.update(content);
  } else if (isReadableStream(content)) {
    const reader = content.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (value !== undefined) {
          hasher.update(value);
        }
      }
    } finally {
      reader.releaseLock();
    }
  } else {
    for await (const chunk of content) {
      hasher.update(chunk);
    }
  }
  const digest = hasher.digest();
  return { algorithm: spec.algorithm, digest, notation: formatContentHash(spec.algorithm, digest) };
}

/** 表記または正規化済み値を `ParsedContentHash` に揃える。 */
function toParsed(expected: string | ParsedContentHash): ParsedContentHash {
  return typeof expected === 'string' ? parseContentHash(expected) : expected;
}

/**
 * 2 つの contentHash を定数時間で照合する。
 *
 * アルゴリズム名・ダイジェストのどちらが食い違っても不一致として扱う。早期 return を
 * 避けるため両方を評価してから判定する。
 *
 * @param a 比較対象。
 * @param b 比較対象。
 * @returns 完全一致なら `true`。
 */
export function contentHashEquals(a: ParsedContentHash, b: ParsedContentHash): boolean {
  const algorithmMatches = timingSafeEqualString(a.algorithm, b.algorithm);
  const digestMatches = timingSafeEqualBytes(a.digest, b.digest);
  return algorithmMatches && digestMatches;
}

/**
 * コンテンツから計算したダイジェストが期待値と一致するか検証する。
 *
 * @param content 検証対象のコンテンツ。
 * @param expected 期待する contentHash（表記文字列または正規化済み値）。
 * @returns 実コンテンツから計算した contentHash。
 * @throws 不一致の場合（VericertsError、code `2009`）。
 * @throws 表記不正 / 未対応アルゴリズムの場合（code `2016` / `1030`）。
 */
export async function verifyContentHash(
  content: ContentSource,
  expected: string | ParsedContentHash,
): Promise<ParsedContentHash> {
  const expectedHash = toParsed(expected);
  const actual = await computeContentHash(content, expectedHash.algorithm);
  if (!contentHashEquals(actual, expectedHash)) {
    throw new VericertsError(ErrorCodes.CONTENT_HASH_MISMATCH);
  }
  return actual;
}

/**
 * content-addressed DID のサブパス hash と実コンテンツの一致を検証する。
 *
 * @param did content-addressed DID（DID URL 可）。
 * @param content 検証対象のコンテンツ。
 * @returns DID サブパスから抽出・正規化した contentHash。
 * @throws 不一致の場合（VericertsError、code `2009`）。
 * @throws DID 形式不正 / 表記不正 / 未対応アルゴリズムの場合（code `2001` / `2016` / `1030`）。
 */
export async function verifyDidContentHash(
  did: string,
  content: ContentSource,
): Promise<ParsedContentHash> {
  const expected = extractDidContentHash(did);
  await verifyContentHash(content, expected);
  return expected;
}

/**
 * Provenance VC の `contentHash` claim と DID サブパスの一致を検証する。
 *
 * コンテンツ本体を必要としない同期 API。表記が違っても（hex / base64url / multibase）
 * 正規化後のダイジェストで比較する。
 *
 * @param did content-addressed DID（DID URL 可）。
 * @param contentHashClaim VC の `contentHash` claim 値。
 * @returns 正規化した contentHash。
 * @throws 不一致の場合（VericertsError、code `2009`）。
 * @throws DID 形式不正 / 表記不正 / 未対応アルゴリズムの場合（code `2001` / `2016` / `1030`）。
 */
export function verifyVcContentHashClaim(did: string, contentHashClaim: string): ParsedContentHash {
  const fromDid = extractDidContentHash(did);
  const fromClaim = parseContentHash(contentHashClaim);
  if (!contentHashEquals(fromDid, fromClaim)) {
    throw new VericertsError(ErrorCodes.CONTENT_HASH_MISMATCH);
  }
  return fromDid;
}
