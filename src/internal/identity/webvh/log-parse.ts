/**
 * did:webvh の DID Log（JSON Lines）パースと、`parameters` の鍵配列の件数上限つき読み取り。
 *
 * パース段階では最小構造（versionId / versionTime / parameters / state）と件数・長さの
 * 上限だけを検査し、`parameters` の値の検証は `./parameters.ts`、署名・ハッシュの検証は `./verify.ts` が行う。
 * 例外メッセージ・`context` に DID 文字列・Log 本文・鍵バイトを含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { WebVhLogEntry } from './codec.js';
import {
  MAX_KEYS_PER_ENTRY,
  MAX_LOG_ENTRIES,
  MAX_LOG_ENTRY_CHARS,
  MAX_PROOFS_PER_ENTRY,
  rejectDidLogOversized,
} from './limits.js';

/**
 * DID Log の JSON Lines テキストをパースする。空行はスキップし、各行を最小構造
 * （versionId / versionTime / parameters / state、state は `id` を持つ）として検証する。
 *
 * @param text JSONL テキスト。
 * @returns パース済みエントリ配列。
 * @throws 行が JSON 不正・必須メンバ欠落・エントリ 0 件、またはエントリ数・1 行の長さが上限超過の場合（VericertsError、code `2001`）。
 */
export function parseDidLog(text: string): WebVhLogEntry[] {
  // 空行・空白のみの行は読み飛ばす（判定の実体は共有ヘルパ）。
  const lines = text.split('\n').filter(isNonBlankString);
  if (lines.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // JSON パース・署名検証より前に、件数・1 行の長さだけで拒否する。
  rejectDidLogOversized(lines.length, MAX_LOG_ENTRIES);
  const entries: WebVhLogEntry[] = [];
  for (const line of lines) {
    rejectDidLogOversized(line.length, MAX_LOG_ENTRY_CHARS);
    let parsed: unknown;
    try {
      parsed = parseJsonWithoutPrototype(line);
    } catch {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    entries.push(toLogEntry(parsed));
  }
  return entries;
}

/**
 * パース済み JSON 値を `WebVhLogEntry` に検証変換する。
 *
 * @param parsed JSON 値。
 * @returns 検証済みエントリ。
 * @throws 構造不正の場合（VericertsError、code `2001`）。
 */
function toLogEntry(parsed: unknown): WebVhLogEntry {
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.versionId !== 'string' || obj.versionId.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (typeof obj.versionTime !== 'string') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (typeof obj.parameters !== 'object' || obj.parameters === null) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  // 鍵ごとの処理（事前コミットのハッシュ）を始める前に、件数だけで拒否する。
  updateKeysOf(parsed as WebVhLogEntry);
  nextKeyHashesOf(parsed as WebVhLogEntry);
  if (typeof obj.state !== 'object' || obj.state === null || Array.isArray(obj.state)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const state = obj.state as Record<string, unknown>;
  if (typeof state.id !== 'string' || state.id.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (Array.isArray(obj.proof)) {
    rejectDidLogOversized(obj.proof.length, MAX_PROOFS_PER_ENTRY);
  }
  // proof は省略可だが、あるなら「非 null オブジェクトの配列」でなければならない（生 TypeError の漏出防止）。
  if (
    obj.proof !== undefined &&
    (!Array.isArray(obj.proof) ||
      obj.proof.some((p) => typeof p !== 'object' || p === null || Array.isArray(p)))
  ) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return parsed as WebVhLogEntry;
}

/**
 * エントリの `parameters.updateKeys` を Set として取り出す。
 *
 * @param entry DID Log エントリ。
 * @returns updateKeys の Set（未指定なら空）。
 */
export function updateKeysOf(entry: WebVhLogEntry): ReadonlySet<string> {
  return boundedStringSet(ownProperty<unknown>(entry.parameters, 'updateKeys')) ?? new Set();
}

/**
 * エントリの `parameters.nextKeyHashes`（次版更新鍵の事前コミット）を Set として取り出す。
 *
 * 未指定なら `undefined` を返す（「事前コミット無し」と「空配列」を区別するため）。
 *
 * @param entry DID Log エントリ。
 * @returns nextKeyHashes の Set。宣言が無ければ `undefined`。
 * @throws 件数が `MAX_KEYS_PER_ENTRY` を超える場合（VericertsError、code `2001`、`did_log_too_large`）。
 */
export function nextKeyHashesOf(entry: WebVhLogEntry): ReadonlySet<string> | undefined {
  return boundedStringSet(ownProperty<unknown>(entry.parameters, 'nextKeyHashes'));
}

/** 鍵配列を文字列の Set にする。配列でなければ `undefined`。件数は走査前に `MAX_KEYS_PER_ENTRY` で縛る。 */
function boundedStringSet(list: unknown): ReadonlySet<string> | undefined {
  if (!Array.isArray(list)) {
    return undefined;
  }
  rejectDidLogOversized(list.length, MAX_KEYS_PER_ENTRY);
  return new Set(list.filter((item): item is string => typeof item === 'string'));
}
