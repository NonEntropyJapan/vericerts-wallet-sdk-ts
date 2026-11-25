/**
 * did:plc の監査ログ（`GET /<did>/log/audit`）の検証（did:plc 仕様「Audit Logs」）。
 *
 * 1. ジェネシス（先頭・`prev: null`）から DID を再計算して一致を確認する。
 * 2. 各操作の `sig` を、直前の操作の `rotationKeys`（ジェネシスは自身のもの）で検証する。どの鍵でも検証できない操作は
 *    ディレクトリが受理してはならないもので、信頼違反として拒否する。
 * 3. ログを作成時刻順に再生して有効な操作列を確定する。`prev` が先端でなければ分岐（回復）で、
 *    - 分岐操作の署名鍵が、先端側（無効化される最初の操作）を署名した鍵より**優先度が高い**（`rotationKeys` の
 *      インデックスが小さい）こと、
 *    - 無効化される最初の操作から 72 時間以内に作成されたこと
 *    を満たすときだけ、それ以降の操作を無効化して分岐を採用する。
 * 4. 再生で得た無効化の集合と、ディレクトリが付けた `nullified` が一致することを確認する。
 *
 * 72 時間の回復窓の内側での分岐は、検証だけでは「どちらが先に受理されたか」を見分けられない
 * （ディレクトリの返す順序を信頼する）。
 *
 * 署名検証は 1 回ごとに解決スコープへ仕事量を計上する。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に DID・操作の内容を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  consumeResolutionWork,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_SIGNATURE,
} from '../resolution-budget.js';
import { type PlcRotationKey, parseRotationKey, verifySignature } from './keys.js';
import { didOfGenesisBytes, isRecord, type ParsedOperation, parseOperation } from './operation.js';

/** 回復窓（ミリ秒）。 */
export const RECOVERY_WINDOW_MS = 72 * 60 * 60 * 1000;
/** 1 DID あたり受理する監査ログの最大件数（署名検証の仕事量の上限）。 */
export const MAX_AUDIT_ENTRIES = 512;

interface ChainEntry {
  readonly op: ParsedOperation;
  /** この操作を署名した `rotationKeys` のインデックス（小さいほど優先度が高い）。 */
  readonly signerIndex: number;
  readonly createdAtMs: number;
}

function invalidLog(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.DID_DOC_INVALID, { context: { reason } });
}

function tryParseRotationKey(didKey: string): PlcRotationKey | undefined {
  try {
    return parseRotationKey(didKey);
  } catch {
    return undefined;
  }
}

/**
 * `sig` を `rotationKeys` の優先度順に試し、検証できた鍵のインデックスを返す。
 * 試行 1 回ごとに署名検証 1 回ぶんの仕事量を計上する。
 */
function findSigner(
  op: ParsedOperation,
  rotationKeys: readonly string[],
  scope: ResolutionWorkBudget | undefined,
): number {
  for (const [index, didKey] of rotationKeys.entries()) {
    consumeResolutionWork(scope, WORK_UNITS_PER_SIGNATURE);
    // 旧形式 create の鍵は構文しか検査していない。署名を検証できない鍵（Ed25519 等）は一致しない鍵として扱う。
    const key = tryParseRotationKey(didKey);
    if (key !== undefined && verifySignature(key, op.unsigned, op.sig)) {
      return index;
    }
  }
  throw invalidLog('plc_signature_invalid');
}

function readEntry(
  raw: unknown,
  did: string,
): { op: ParsedOperation; nullified: boolean; createdAtMs: number } {
  if (
    !isRecord(raw) ||
    raw.did !== did ||
    typeof raw.cid !== 'string' ||
    typeof raw.nullified !== 'boolean'
  ) {
    throw invalidLog('plc_audit_log_invalid');
  }
  const createdAtMs = typeof raw.createdAt === 'string' ? Date.parse(raw.createdAt) : Number.NaN;
  if (!Number.isFinite(createdAtMs)) {
    throw invalidLog('plc_audit_log_invalid');
  }
  let op: ParsedOperation;
  try {
    op = parseOperation(raw.operation);
  } catch {
    throw invalidLog('plc_audit_log_invalid');
  }
  if (op.cid !== raw.cid) {
    throw invalidLog('plc_cid_mismatch');
  }
  return { op, nullified: raw.nullified, createdAtMs };
}

/**
 * 監査ログを検証し、有効な操作列の最終操作を返す。
 *
 * @param did 解決対象の DID。
 * @param rawEntries 監査ログ（JSON としてパース済みの配列）。
 * @param scope 解決スコープの予算。署名検証 1 回ごとに計上する。
 * @returns 有効な操作列の最終操作。
 * @throws 構造・DID 再計算・署名・分岐規則・`nullified` の不一致（VericertsError、code `2010`、
 *         `context.reason` で区分）、予算超過（code `2001`、`resolution_work_limit`）。
 */
export function verifyAuditLog(
  did: string,
  rawEntries: unknown,
  scope?: ResolutionWorkBudget,
): ParsedOperation {
  if (
    !Array.isArray(rawEntries) ||
    rawEntries.length === 0 ||
    rawEntries.length > MAX_AUDIT_ENTRIES
  ) {
    throw invalidLog('plc_audit_log_invalid');
  }
  const entries = rawEntries.map((raw) => readEntry(raw, did));
  const chain: ChainEntry[] = [];
  const nullifiedCids = new Set<string>();
  const seenCids = new Set<string>();
  let previousCreatedAtMs = Number.NEGATIVE_INFINITY;
  for (const { op, createdAtMs } of entries) {
    if (seenCids.has(op.cid) || createdAtMs < previousCreatedAtMs) {
      throw invalidLog('plc_audit_log_invalid');
    }
    seenCids.add(op.cid);
    previousCreatedAtMs = createdAtMs;
    chain.push(appendOperation(did, chain, op, createdAtMs, nullifiedCids, scope));
  }
  if (entries.some(({ op, nullified }) => nullified !== nullifiedCids.has(op.cid))) {
    throw invalidLog('plc_nullified_mismatch');
  }
  return (chain[chain.length - 1] as ChainEntry).op;
}

/** 操作 1 件を再生中の有効な操作列へ追加する検査（分岐なら無効化を確定し、`chain` を切り詰める）。 */
function appendOperation(
  did: string,
  chain: ChainEntry[],
  op: ParsedOperation,
  createdAtMs: number,
  nullifiedCids: Set<string>,
  scope: ResolutionWorkBudget | undefined,
): ChainEntry {
  if (chain.length === 0) {
    // ジェネシスは `prev: null` で、tombstone ではなく、DID が再計算と一致すること。
    if (op.prev !== null || op.data === undefined) {
      throw invalidLog('plc_audit_log_invalid');
    }
    if (didOfGenesisBytes(op.signed) !== did) {
      throw invalidLog('plc_did_mismatch');
    }
    return { op, signerIndex: findSigner(op, op.data.rotationKeys, scope), createdAtMs };
  }
  const prevIndex = chain.findIndex((entry) => entry.op.cid === op.prev);
  const prevEntry = chain[prevIndex];
  // 先頭以外の `prev: null`、無効化済み / 未知の `prev`、tombstone の後ろへの追加は受理されない。
  if (prevEntry === undefined || prevEntry.op.data === undefined) {
    throw invalidLog('plc_prev_invalid');
  }
  const signerIndex = findSigner(op, prevEntry.op.data.rotationKeys, scope);
  const firstNullified = chain[prevIndex + 1];
  if (firstNullified !== undefined) {
    const withinWindow = createdAtMs - firstNullified.createdAtMs <= RECOVERY_WINDOW_MS;
    if (signerIndex >= firstNullified.signerIndex || !withinWindow) {
      throw invalidLog('plc_recovery_invalid');
    }
    for (const nullified of chain.splice(prevIndex + 1)) {
      nullifiedCids.add(nullified.op.cid);
    }
  }
  return { op, signerIndex, createdAtMs };
}
