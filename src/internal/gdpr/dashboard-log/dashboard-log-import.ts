/**
 * Dashboard ログの JWS-signed NDJSON エクスポートを検証しつつインポート用に
 * パースするヘルパ。`exportLog`（dashboard-log.ts）が生成した NDJSON テキストを入力とする。
 *
 * 各行を `DashboardLogEntry` へ復元し、以下 3 点をすべて検証する（1 つでも失敗すればインポートを拒否）:
 * 1. 各エントリの JWS 署名: `signature`（`header.payload.sig`）を `decodeCompactJws` で分解し、
 *    署名対象 payload（`type` / `payload` / `recordedAt` / `prevHash`）が本文フィールドと一致することを
 *    確認したうえで、呼び出し側が渡す検証鍵（署名時のペルソナ公開鍵 JWK）で署名を検証する。
 * 2. Merkle（ハッシュ）chain: 先頭エントリの `prevHash` は `null`、以降は直前エントリの signing-input
 *    SHA-256（base64url）と一致する（export と同一計算）。ルートハッシュ行に `partial: true` がある
 *    欠損付きエクスポート（絞り込み・削除済み、`dashboard-log-export.ts`）は、先頭 `null` と
 *    全行の隣接性の要求を外し、連番が隣り合う行どうしの `prevHash` のみを要求する（下記）。
 * 3. Merkle ルートハッシュ行: 末尾行 `{ merkleRoot, count }` の `count` がエントリ数、`merkleRoot` が
 *    最終エントリの signing-input SHA-256（0 件時は `null`）と一致する。
 *
 * 検証に成功したエントリ列を返す（インポート永続化は `DashboardLog.importLog` が担う）。改ざん検知は
 * 入力由来の失敗のため、message / cause に元データを載せず `VericertsError` に正規化する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import {
  type DashboardLogVerifierKey,
  seqOf,
  verifyEntrySignature,
} from '../log-integrity/entry-signature.js';
import type { DashboardLogEntry } from '../types.js';
import { seqToId, signingInputHash } from './dashboard-log-shared.js';

/**
 * 署名検証鍵の型。実体は `log-integrity/entry-signature.ts`（保存済みログの chain 検証と共有するため）。
 * 既存の import パス（`dashboard-log-import.js`）を保つために再エクスポートする。
 */
export type { DashboardLogVerifierKey };

/** export NDJSON 末尾に付与される Merkle ルートハッシュ行。 */
interface MerkleRootLine {
  /** 最終エントリの signing-input の SHA-256（base64url）。0 件時は `null`。 */
  readonly merkleRoot: string | null;
  /** エントリ数（ルートハッシュ行を除く行数）。 */
  readonly count: number;
  /** chain に欠損のあるエクスポート（絞り込み・削除済み）。`true` のときだけ付く。 */
  readonly partial?: true;
}

/** 値が `DashboardLogEntry` の必須フィールドを満たすかを検証する型ガード。 */
function isDashboardLogEntry(value: unknown): value is DashboardLogEntry {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === 'string' &&
    typeof v.type === 'string' &&
    typeof v.recordedAt === 'string' &&
    typeof v.payload === 'object' &&
    v.payload !== null &&
    (v.prevHash === null || typeof v.prevHash === 'string') &&
    typeof v.signature === 'string'
  );
}

/** 値が Merkle ルートハッシュ行の形を満たすかを検証する型ガード。 */
function isMerkleRootLine(value: unknown): value is MerkleRootLine {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    (v.merkleRoot === null || typeof v.merkleRoot === 'string') &&
    typeof v.count === 'number' &&
    (v.partial === undefined || v.partial === true)
  );
}

/** NDJSON テキストを 1 行 1 JSON でパースする（空文字は空配列）。 */
function parseNdjson(ndjson: string): unknown[] {
  if (ndjson === '') {
    // 末尾ルートハッシュ行が必須のため空入力は不正。呼び出し側でルートハッシュ行欠落として弾く。
    return [];
  }
  return ndjson.split('\n').map((line) => {
    try {
      return parseJsonWithoutPrototype(line);
    } catch {
      // 破損行の内容は載せず形式不正へ正規化する。
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
  });
}

/**
 * 欠損のない export の chain 検証: 先頭 `prevHash` は `null`、以降は直前行のハッシュと一致する。
 * 保存先の連番は追記順（0 起点）に振り直す（`id` は署名対象外のため入力値を信用しない）。
 */
function verifyContinuousChain(lines: readonly unknown[]): DashboardLogEntry[] {
  const entries: DashboardLogEntry[] = [];
  let prevHash: string | null = null;
  for (const line of lines) {
    if (!isDashboardLogEntry(line)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    if (line.prevHash !== prevHash) {
      throw new VericertsError(ErrorCodes.SIG_INVALID);
    }
    prevHash = signingInputHash(line);
    entries.push({ ...line, id: seqToId(entries.length) });
  }
  return entries;
}

/**
 * `partial: true` の export の chain 検証。欠損区間の前後は照合できないので、
 * - `id` はゼロ埋め連番で、行の並びに沿って厳密に増える（元の連番を保って取り込む。振り直すと
 *   欠損位置の `prevHash` と連番がずれる）、
 * - 連番 0 の行は `prevHash: null`、
 * - 連番が隣り合う行どうしは `prevHash` が直前行のハッシュと一致する、
 * ことだけを要求する。各行の署名は呼び出し側が検証する（行の改ざんは署名検証で `3010`）。
 */
function verifyPartialChain(lines: readonly unknown[]): DashboardLogEntry[] {
  const entries: DashboardLogEntry[] = [];
  for (const line of lines) {
    if (!isDashboardLogEntry(line)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    const seq = seqOf(line.id);
    if (seq === undefined || line.id !== seqToId(seq)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    const previous = entries[entries.length - 1];
    const previousSeq = previous === undefined ? undefined : seqOf(previous.id);
    if (previous !== undefined && previousSeq !== undefined) {
      if (seq <= previousSeq) {
        throw new VericertsError(ErrorCodes.SIG_INVALID);
      }
      if (seq === previousSeq + 1 && line.prevHash !== signingInputHash(previous)) {
        throw new VericertsError(ErrorCodes.SIG_INVALID);
      }
    }
    if (seq === 0 && line.prevHash !== null) {
      throw new VericertsError(ErrorCodes.SIG_INVALID);
    }
    entries.push(line);
  }
  return entries;
}

/**
 * JWS-signed NDJSON エクスポートを検証し、検証済みエントリ列を返す。
 *
 * 各エントリの JWS 署名（`verifierKey` で検証）・Merkle prevHash chain の連続性・末尾ルートハッシュ行を
 * すべて検証する。1 つでも失敗すればインポートを拒否する。
 *
 * @param ndjson `exportLog` が生成した NDJSON テキスト（各行が JWS 署名付きエントリ、末尾行がルートハッシュ）。
 * @param verifierKey 署名検証鍵（署名時のペルソナ / エフェメラル公開鍵）。
 * @returns 検証に成功したエントリ列（追記順）。
 * @throws NDJSON 形式不正・ルートハッシュ行欠落の場合（VericertsError、`ErrorCodes.INVALID_DID` = `2001`）、
 *         署名検証失敗・Merkle chain / ルートハッシュ不一致の場合（`ErrorCodes.SIG_INVALID` = `3010`）。
 */
export function verifyDashboardLogExport(
  ndjson: string,
  verifierKey: DashboardLogVerifierKey,
): DashboardLogEntry[] {
  const lines = parseNdjson(ndjson);
  // 末尾は必ず Merkle ルートハッシュ行。最低 1 行（0 件エクスポートでもルートハッシュ行は存在する）。
  const rootLine = lines[lines.length - 1];
  if (lines.length === 0 || !isMerkleRootLine(rootLine)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const entryLines = lines.slice(0, -1);
  if (entryLines.length !== rootLine.count) {
    // ルートハッシュ行の count がエントリ数と食い違う（行の欠落 / 混入）。
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }

  const entries =
    ownProperty<boolean>(rootLine, 'partial') === true
      ? verifyPartialChain(entryLines)
      : verifyContinuousChain(entryLines);
  for (const entry of entries) {
    // JWS 署名検証（本文一致 + 署名有効性）。
    if (!verifyEntrySignature(entry, verifierKey)) {
      throw new VericertsError(ErrorCodes.SIG_INVALID);
    }
  }

  // Merkle ルートハッシュ: 最終エントリの signing-input SHA-256（0 件時は null）と一致する。
  const expectedRoot =
    entries.length === 0
      ? null
      : signingInputHash(entries[entries.length - 1] as DashboardLogEntry);
  if (rootLine.merkleRoot !== expectedRoot) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  return entries;
}
