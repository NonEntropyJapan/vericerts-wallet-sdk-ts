/**
 * did:webvh の DID Log 検証量の上限。
 *
 * DID Log の取得先は受領した VC / VP の `iss` 由来で攻撃者が選べる。本文上限（`MAX_DOCUMENT_BYTES` = 1 MiB）
 * だけでは、約 520 KB の state に約 1,500 個の「許可鍵を名乗るが署名が不正な」proof を並べた 1 通で、proof ごとに
 * payload 全体を SHA-512 に掛ける検証が約 11.5 秒同期 CPU を占有した。署名検証より前に件数・サイズだけで拒否する。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import {
  consumeResolutionWork,
  type ResolutionWorkBudget,
  WORK_UNITS_PER_KEY_HASH,
  WORK_UNITS_PER_SIGNATURE,
} from '../resolution-budget.js';

/** 上限超過で `INVALID_DID`（2001）に倒す際の `context.reason`（DID・Log 本文は含めない）。 */
const DID_LOG_TOO_LARGE = { reason: 'did_log_too_large' } as const;

/**
 * 1 エントリの `proof[]` の最大件数。実在のエントリは updateKeys の閾値ぶん（通常 1 件）しか持たない。
 * 検証する署名数を「proof 件数」ではなくこの定数で縛る。
 */
export const MAX_PROOFS_PER_ENTRY = 8;

/**
 * DID Log の最大エントリ（版）数。1 エントリ 1 署名検証（Node で約 1.5 ms）なので、上限一杯でも
 * 約 0.8 秒に収まる値にしてある（1,024 だと約 1.5 秒）。実在の DID が 512 版を超えることは無い。
 * 署名検証の総数は別途 `createSignatureBudget` で縛る。
 */
export const MAX_LOG_ENTRIES = 512;

/**
 * 1 エントリ（JSONL 1 行 / 署名対象 payload の正規化文字列）の最大長（UTF-16 コード単位）。
 * 実在の DID Document は数 KB。proof ごとにこの payload を再ハッシュするため、巨大 state を縛る。
 */
export const MAX_LOG_ENTRY_CHARS = 131_072;

/**
 * ログ全体の署名検証回数が「エントリ数」を超えてよい余剰。正規のエントリは先頭の許可鍵 proof 1 件で
 * 検証が終わる（1 エントリ 1 検証）ので、総検証数の予算は `entries.length + この値` で足りる。
 * 「許可鍵を名乗る不正 proof を 7 個 + 正規 1 個」を全エントリに置いて 1 エントリあたり最大 8 検証を強いる
 * 攻撃（8 proof × 359 エントリで Node が約 4.4 秒停止）は、数エントリで予算を使い切って拒否される。
 */
export const SIGNATURE_BUDGET_SLACK = MAX_PROOFS_PER_ENTRY;

/**
 * DID Log 1 本の署名検証の残り回数（`verifyChain` が作り、各エントリの `verifyEntryProof` が消費する）。
 * `scope` はスコープ全体（VP 1 件 / DLC 検証 1 回）の仕事量予算で、あれば同じ検証を `WORK_UNITS_PER_SIGNATURE`
 * そちらにも計上する。ログ 1 本の上限は DID Log ごとに作り直され、複数の DID にまたがる総量は縛れないため。
 */
export interface SignatureBudget {
  remaining: number;
  readonly scope?: ResolutionWorkBudget;
}

/** `entryCount` 件のログ向けの署名検証予算を作る。 */
export function createSignatureBudget(
  entryCount: number,
  scope?: ResolutionWorkBudget,
): SignatureBudget {
  const remaining = entryCount + SIGNATURE_BUDGET_SLACK;
  return scope === undefined ? { remaining } : { remaining, scope };
}

/** 予算を 1 回ぶん消費する。尽きていたら署名を検証せず `INVALID_DID`（`did_log_too_large` / `resolution_work_limit`）で拒否する。 */
export function consumeSignatureBudget(budget: SignatureBudget): void {
  rejectDidLogOversized(1, budget.remaining);
  consumeResolutionWork(budget.scope, WORK_UNITS_PER_SIGNATURE);
  budget.remaining -= 1;
}

/**
 * 1 エントリの `parameters.updateKeys` / `nextKeyHashes` の最大件数。実在の DID は 1〜3 件。
 * 事前コミット検証（`verifyKeyPreCommit`）は宣言された鍵ごとに SHA-256 + base58 を計算するため、
 * 件数が無制限だと 1 MiB 未満のログで 512 版 × 230 鍵（約 12 万回）= Node で約 1.2 秒の同期 CPU を占有できた。
 * 件数の超過は `toLogEntry` / `updateKeysOf` / `nextKeyHashesOf` がハッシュ計算・署名検証より前に拒否する。
 */
export const MAX_KEYS_PER_ENTRY = 32;

/**
 * ログ全体の事前コミット用鍵ハッシュ（`updateKeyHash`）の計算回数の上限。1 回 Node で約 10 μs なので、
 * 上限一杯でも約 40 ms に収まる値にしてある。正規のログは 1 版あたり数鍵しか事前コミット検証を受けない
 * （512 版 × 8 鍵、または 128 版 × 32 鍵まで通る）。1 エントリの件数上限（`MAX_KEYS_PER_ENTRY`）だけでは
 * 全エントリに上限一杯の鍵を並べて総数を 512 × 32 まで膨らませられるため、総数として縛る。
 */
export const MAX_KEY_HASHES_PER_LOG = 4096;

/**
 * DID Log 1 本の事前コミット用鍵ハッシュ計算の残り回数（`verifyChain` が作り、`verifyKeyPreCommit` が消費する）。
 * `scope` はスコープ全体（VP 1 件 / DLC 検証 1 回）の仕事量予算で、あれば同じ回数をそちらにも計上する。
 */
export interface KeyHashBudget {
  remaining: number;
  readonly scope?: ResolutionWorkBudget;
}

/** 鍵ハッシュ計算の予算（ログ 1 本ぶん）を作る。 */
export function createKeyHashBudget(scope?: ResolutionWorkBudget): KeyHashBudget {
  return scope === undefined
    ? { remaining: MAX_KEY_HASHES_PER_LOG }
    : { remaining: MAX_KEY_HASHES_PER_LOG, scope };
}

/** 鍵ハッシュ計算を 1 回ぶん消費する。尽きていたらハッシュを計算せず `INVALID_DID` で拒否する。 */
export function consumeKeyHashBudget(budget: KeyHashBudget): void {
  rejectDidLogOversized(1, budget.remaining);
  consumeResolutionWork(budget.scope, WORK_UNITS_PER_KEY_HASH);
  budget.remaining -= 1;
}

/**
 * 1 エントリの `parameters.witness.witnesses` の最大件数。実在の構成は 1〜数件。witness パラメータの検証は
 * 各 `did:key` の base58 デコードを伴うので、件数を縛る（検証済み id は同じログ内で再検証しない）。
 */
export const MAX_WITNESSES_PER_ENTRY = 32;

/** 1 エントリの `parameters.watchers` の最大件数。 */
export const MAX_WATCHERS_PER_ENTRY = 32;

/** watcher URL 1 件の最大長（UTF-16 コード単位）。 */
export const MAX_WATCHER_URL_CHARS = 2048;

/**
 * `did-witness.json` の最大項目数（`{ versionId, proof[] }` の件数）。公開済みの版ごとに 1 項目まで
 * （仕様はコントローラに「witness ごとに最新の 1 件だけ残す」剪定を求めるが、未剪定でも版数までは許す）。
 * 版数上限（`MAX_LOG_ENTRIES`）と同じ値にして、全版ぶんの項目を持つ正当なファイルを拒否しない。
 */
export const MAX_WITNESS_FILE_ITEMS = MAX_LOG_ENTRIES;

/** `did-witness.json` の 1 項目あたりの最大 proof 件数。witness 数の上限の 2 倍（同じ witness の重複を見込む）。 */
export const MAX_WITNESS_PROOFS_PER_ITEM = MAX_WITNESSES_PER_ENTRY * 2;

/** `did-witness.json` 全体の最大 proof 件数。構造検査（署名検証の前）で件数だけで拒否する。 */
export const MAX_WITNESS_FILE_PROOFS = 1024;

/**
 * witness proof の署名検証回数の上限（ログ 1 本ぶん）。1 回 Node で約 1.5 ms なので上限一杯でも約 0.4 秒に収まる。
 * 署名検証は witness ごとに「最新の proof から順に、最初に有効なものまで」しか行わない（有効な proof が 1 件あれば、それ以前の
 * 版への承認も含意される。仕様 Witness Proofs File）ため、剪定済みのファイルなら witness 数ぶんで足りる。
 */
export const MAX_WITNESS_SIGNATURES_PER_LOG = 256;

/** witness proof 用の署名検証予算（ログ 1 本ぶん）を作る。`scope` があれば同じ検証をスコープ全体の予算にも計上する。 */
export function createWitnessSignatureBudget(scope?: ResolutionWorkBudget): SignatureBudget {
  return scope === undefined
    ? { remaining: MAX_WITNESS_SIGNATURES_PER_LOG }
    : { remaining: MAX_WITNESS_SIGNATURES_PER_LOG, scope };
}

/** `size` が `max` を超えるなら `INVALID_DID`（2001、`reason: 'did_log_too_large'`）。 */
export function rejectDidLogOversized(size: number, max: number): void {
  if (size > max) {
    throw new VericertsError(ErrorCodes.INVALID_DID, { context: DID_LOG_TOO_LARGE });
  }
}
