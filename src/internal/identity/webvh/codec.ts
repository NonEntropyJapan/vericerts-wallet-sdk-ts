/**
 * did:webvh の正規化（簡易 JCS）・multihash・Log パースの低レベルヘルパ。
 *
 * 検証（`./verify.ts`）とメソッドプラグイン
 * （`method-webvh.ts`）から共有される純粋関数群。DID 構文/URL マッピングは `did-url.ts`、SHA-256 multihash は
 * `multihash.ts` に分割し、後方互換のため本ファイルから再エクスポートする（1 ファイル 300 行以下のため）。
 * 正規化は RFC 8785（JCS）、ハッシュは DIF didwebvh v1.0 の SCID / Entry Hash / Pre-Rotation Key Hash の定義に従う。
 * 例外メッセージ・`context` に DID 文字列・URL・Log 本文・鍵バイトを含めない。
 */

import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import { ErrorCodes, VericertsError } from '../../errors.js';
import type { DIDDocument } from '../did.js';

export {
  DID_WEBVH_PREFIX,
  DID_WITNESS_MEDIA_TYPES,
  fetchDidLog,
  type ParsedWebVh,
  parseWebVh,
  webVhLogUrl,
  webVhWitnessUrl,
} from './did-url.js';
export { nextKeyHashesOf, parseDidLog, updateKeysOf } from './log-parse.js';
export { multihashBase58, multihashOfText } from './multihash.js';

import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import { multihashOfText } from './multihash.js';

/** scid を差し込むためのプレースホルダ（self-certifying 計算用）。 */
export const SCID_PLACEHOLDER = '{SCID}';

/** DID Log の 1 エントリ（1 行）。 */
export interface WebVhLogEntry {
  /** バージョン識別子（`<n>-<hash>`）。 */
  readonly versionId: string;
  /** ISO 8601 のバージョン時刻。 */
  readonly versionTime: string;
  /** この版で適用されるパラメータ。 */
  readonly parameters: WebVhParameters;
  /** この版の DID Document（state）。 */
  readonly state: DIDDocument;
  /** Data Integrity proof（全エントリ必須。検証側が欠落を拒否する）。 */
  readonly proof?: readonly WebVhProof[];
}

/**
 * DID Log エントリの parameters 部（生の JSON。値の検証と既定値の補完は `./parameters.ts`）。
 *
 * 仕様（`did:webvh` DID Method Parameters）の定義: `method` / `scid` / `updateKeys` / `nextKeyHashes` / `witness` /
 * `watchers` / `portable` / `deactivated` / `ttl`。省略は「前の値を維持」（初版は既定値）。
 */
export interface WebVhParameters {
  /** メソッドバージョン。`did:webvh:1.0` のみ（初版で必須）。 */
  readonly method?: string;
  /** scid（初版でのみ。後続の版では指定不可）。 */
  readonly scid?: string;
  /** この版以降で有効な更新鍵（Multikey 文字列）。 */
  readonly updateKeys?: readonly string[];
  /** 次版の更新鍵ハッシュ（事前コミット用）。空配列で事前コミットを解除する。 */
  readonly nextKeyHashes?: readonly string[];
  /** witness の構成（`{}` で witness なし）。 */
  readonly witness?: WebVhWitnessParameter;
  /** watcher の URL 一覧（`[]` で解除）。 */
  readonly watchers?: readonly string[];
  /** 移動（`state.id` の host / path の変更）を許すか。`true` にできるのは初版だけ。 */
  readonly portable?: boolean;
  /** 失効。`true` で以降の更新は不可。 */
  readonly deactivated?: boolean;
  /** キャッシュ秒数（0〜2^31）。 */
  readonly ttl?: number;
  readonly [key: string]: unknown;
}

/** `parameters.witness`（`{}` または `{ threshold, witnesses: [{ id: <did:key> }] }`）。 */
export interface WebVhWitnessParameter {
  readonly threshold?: number;
  readonly witnesses?: readonly { readonly id: string }[];
}

/** Data Integrity proof（eddsa-jcs-2022 相当）。 */
export interface WebVhProof {
  /** 検証メソッド参照（`<multikey>` / `did:key:<multikey>#<multikey>`）。 */
  readonly verificationMethod: string;
  /** multibase base58btc 署名（`z...`）。 */
  readonly proofValue: string;
  readonly [key: string]: unknown;
}

/**
 * 値を簡易 JCS（RFC 8785 相当・キーソート済み JSON）で正規化する。オブジェクトキーは
 * コードポイント順、配列順序は保持、`undefined` は出力しない。NaN / Infinity・function /
 * symbol は不正。
 *
 * @param value 正規化対象。
 * @returns 正規化済み JSON 文字列。
 * @throws 数値が有限でない / JSON 非表現値の場合（VericertsError、code `2001`）。
 */
export function canonicalize(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  const valueType = typeof value;
  if (valueType === 'number') {
    if (!Number.isFinite(value)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    return JSON.stringify(value);
  }
  if (valueType === 'string' || valueType === 'boolean') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalize(item === undefined ? null : item));
    return `[${items.join(',')}]`;
  }
  if (valueType === 'object') {
    const obj = value as Record<string, unknown>;
    const members: string[] = [];
    for (const key of Object.keys(obj).sort()) {
      const member = obj[key];
      if (member === undefined) {
        continue;
      }
      members.push(`${JSON.stringify(key)}:${canonicalize(member)}`);
    }
    return `{${members.join(',')}}`;
  }
  throw new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * エントリから `proof` を除いた写しを作る（署名対象・ハッシュ対象の基になる。`versionId` は残す）。
 *
 * @param entry DID Log エントリ。
 * @returns `proof` を除いたエントリの shallow copy。
 */
export function entryWithoutProof(entry: WebVhLogEntry): Record<string, unknown> {
  const { proof: _proof, ...rest } = entry as WebVhLogEntry & Record<string, unknown>;
  return rest;
}

/**
 * 1 エントリの versionId（`<n>-<entryHash>`）を計算する。
 *
 * entryHash は `base58btc(multihash(JCS(entry)))`。ハッシュ対象の `entry` は `proof` を除いたエントリで、
 * `versionId` には**直前の識別子**（初版は SCID、以降は前版の versionId）を入れたもの
 * （spec: Entry Hash Generation and Verification）。
 *
 * @param entry 対象エントリ（`versionId` は無視される）。
 * @param versionNumber バージョン番号（1 始まり）。
 * @param previousId 直前識別子（初版は SCID）。
 * @returns versionId。
 */
export function deriveVersionId(
  entry: WebVhLogEntry,
  versionNumber: number,
  previousId: string,
): string {
  const hashInput = canonicalize({ ...entryWithoutProof(entry), versionId: previousId });
  return `${versionNumber}-${multihashOfText(hashInput)}`;
}

/**
 * SCID を `base58btc(multihash(JCS(preliminary entry)))` で計算する（spec: Generate SCID）。
 *
 * @param preliminary `versionId` が `{SCID}`、`proof` を持たず、SCID を入れる全箇所が `{SCID}` のエントリ。
 */
export function computeScid(preliminary: Record<string, unknown>): string {
  return multihashOfText(canonicalize(preliminary));
}

/**
 * 文字列としての置換（`from` の全出現を `to` に）を JSON 値へ適用して、新しい値を返す。
 *
 * 仕様の SCID 検証（Verify SCID の 6）と生成（Create の 5.2）は「エントリを文字列として扱ってリテラル置換する」
 * ことを求める。キー名に現れる文字列も置換される（JCS のキー順が変わりうる）ため、JSON 文字列化 → 置換 →
 * 再パースで仕様どおりに行う。
 */
export function replaceInJson<T>(value: T, from: string, to: string): T {
  return parseJsonWithoutPrototype(JSON.stringify(value).split(from).join(to)) as T;
}

/**
 * versionId（`<n>-<hash>`）からバージョン番号を取り出す。
 *
 * @param versionId versionId 文字列。
 * @returns バージョン番号。
 * @throws 形式不正・非正整数の場合（VericertsError、code `2001`）。
 */
export function versionNumberOf(versionId: string): number {
  const dashIndex = versionId.indexOf('-');
  if (dashIndex <= 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const prefix = versionId.slice(0, dashIndex);
  if (!/^[1-9][0-9]*$/.test(prefix)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return Number.parseInt(prefix, 10);
}

/**
 * 次版の既定 versionTime（現在時刻）を返す。前版の versionTime が現在時刻以降（同一ミリ秒を含む）
 * なら、検証側の「versionTime は前版より厳密に大きい」規則（`verifyChain`）を満たすよう前版 + 1ms にする。
 *
 * @param previousVersionTime 前版の `versionTime`。
 * @returns ISO 8601 の versionTime。
 */
export function nextVersionTime(previousVersionTime: string): string {
  const earliestMillis = parseIsoDateTimeMs(previousVersionTime) + 1;
  // 前版が解釈不能（NaN）なら現在時刻。検証側がその Log を拒否するので生成側は何も足さない。
  return new Date(
    Number.isNaN(earliestMillis) ? Date.now() : Math.max(Date.now(), earliestMillis),
  ).toISOString();
}

/**
 * 更新鍵（Multikey 文字列）の事前コミット用ハッシュ（multihash base58btc）を計算する。
 *
 * did:webvh の `nextKeyHashes` は `base58btc(multihash(multikey))`（Multikey 文字列を UTF-8 としてハッシュ。
 * spec: Pre-Rotation Key Hash Generation and Verification）なので、本関数の出力と突き合わせる。
 *
 * @param multikey 更新鍵の Multikey 文字列（`z...`）。
 * @returns base58btc 文字列（`z` プレフィックスなし）。
 */
export function updateKeyHash(multikey: string): string {
  return multihashOfText(multikey);
}
