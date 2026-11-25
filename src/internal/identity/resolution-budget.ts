/**
 * DID 解決 1 スコープ（VP 1 件 / `verifyDIDConfiguration` 1 回）全体の検証仕事量の予算。
 *
 * `createBoundedResolver` は相異なる DID 数と DID 文字長の合計だけを縛るので、1 件ごとの解決コストが
 * 大きい DID（did:webvh は 1 本で最大 512 版 = 署名検証 512 回、Node で約 0.8〜1 秒）を
 * 32 個並べると、署名検証の前でも後でも合計は 32 倍に増幅する（26 秒）。解決 1 回あたりの上限
 * （`webvh/limits.ts`）はスコープをまたいで効かないため、スコープで共有する予算を別に持つ。
 *
 * 単位は「署名検証 1 回 = `WORK_UNITS_PER_SIGNATURE`、鍵ハッシュ 1 回 = `WORK_UNITS_PER_KEY_HASH`」で、
 * Node での実コスト比（署名検証 約 1.5 ms、鍵ハッシュ 約 10 μs）に合わせてある。実時間ではなく決定的な
 * 回数で数えるので、テストは回数・例外の種別で pin できる。
 *
 * 仕事量とは別に、**取得して保持した本文の文字数の合計**（`remainingBodyLength`）も数える。did:web は
 * 署名検証が無く、`did.json`（最大 1 MiB）を `JSON.parse` した文書がスコープの間ずっと保持されるため、相異なる
 * did:web を 32 件並べるだけで署名検証前に 1 GB 級のヒープを占有できた。本文を読み終えたら**パースより前に**計上する。
 *
 * セキュリティ上の注意: 例外の `context` に DID 文字列を含めない（resolver.ts 冒頭と同じ制約）。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

/** 署名検証 1 回ぶんの仕事量。 */
export const WORK_UNITS_PER_SIGNATURE = 100;

/** 事前コミット用の鍵ハッシュ 1 回ぶんの仕事量。 */
export const WORK_UNITS_PER_KEY_HASH = 1;

/**
 * did:ethr の ERC-1056 ログ 1 件の ABI デコード + 文書への反映ぶんの仕事量。Node での実コスト
 * （約 0.1〜0.17 ms）を署名検証 1 回（約 1.5 ms = 100）に対する比で 10 とした。990 件 × 相異なる 32 DID は
 * 約 10 DID ぶんで予算に達し、署名検証前に 3.4 秒止まる増幅を断つ。
 */
export const WORK_UNITS_PER_EVENT_DECODE = 10;

/**
 * ERC-1056 の owner 連鎖を 1 段（identity 1 つ）たどるぶんの仕事量。1 段は `eth_getLogs` 2 本の
 * RPC 往復（最大 10 秒・1 MiB）で、デコードの前に既に計上するイベント分とは別の「往復そのもの」のコスト。
 * 署名検証 1 回と同じ 100 とし、スコープを共有する呼び出しでは連鎖が長い DID ほど予算を食う。
 */
export const WORK_UNITS_PER_OWNER_LOOKUP = 100;

/**
 * 1 スコープで許す仕事量（署名検証 1,024 回ぶん。Node で約 1.5 秒）。正規の解決は 1 DID あたり数版・数署名なので、
 * 数十個の発行者 DID を解決しても収まる。
 */
export const DEFAULT_MAX_SCOPE_WORK_UNITS = 1024 * WORK_UNITS_PER_SIGNATURE;

/**
 * 1 スコープで取得・保持を許す DID Document / DID Log 本文の文字数合計（4 MiB）。正規の DID Document は
 * 数 KB、DID Log も数 KB〜数十 KB なので、数十個の発行者 DID を解決しても収まる。1 件の上限
 * （`MAX_DOCUMENT_BYTES` = 1 MiB）だけでは、相異なる DID 32 件ぶんの 32 MiB を `JSON.parse` して保持できてしまう。
 */
export const DEFAULT_MAX_SCOPE_BODY_LENGTH = 4 * 1024 * 1024;

/** DID 解決スコープの仕事量・本文量の残り（`createBoundedResolver` が作り、各 DID メソッドが消費する）。 */
export interface ResolutionWorkBudget {
  remaining: number;
  /** 取得した本文（DID Document / DID Log）の文字数の残り。 */
  remainingBodyLength: number;
}

/** `maxUnits` ぶんの仕事量と `maxBodyLength` 文字ぶんの本文量の予算を作る。 */
export function createResolutionWorkBudget(
  maxUnits: number = DEFAULT_MAX_SCOPE_WORK_UNITS,
  maxBodyLength: number = DEFAULT_MAX_SCOPE_BODY_LENGTH,
): ResolutionWorkBudget {
  return { remaining: maxUnits, remainingBodyLength: maxBodyLength };
}

/**
 * 取得した本文 `length` 文字ぶんを消費する。`budget` が無い呼び出し（スコープ外の単独解決）は計上しない。
 * 残りが足りなければ残りを 0 にして `INVALID_DID`（`context.reason: 'resolution_work_limit'`）で拒否する。
 * 呼び出し側は**本文を読み終えた直後・パースの前**に呼ぶ（パースのヒープ増幅より前に拒否するため）。
 *
 * @throws 残りが `length` に足りない場合（VericertsError、code `2001`）。
 */
export function consumeResolutionBody(
  budget: ResolutionWorkBudget | undefined,
  length: number,
): void {
  if (budget === undefined) {
    return;
  }
  if (length > budget.remainingBodyLength) {
    // 予算を超える本文を返す取得先があったスコープは使い切ったものとして扱い、以後の取得を始めさせない。
    budget.remainingBodyLength = 0;
    throw new VericertsError(ErrorCodes.INVALID_DID, {
      context: { reason: 'resolution_work_limit' },
    });
  }
  budget.remainingBodyLength -= length;
}

/**
 * 少なくとも `units` ぶんの仕事量と、1 文字以上の本文量が残っていることを確かめる（消費はしない）。DID Log の取得（最大 1 MiB の
 * 外部 I/O）の前に呼び、予算が尽きたスコープでは取得自体を始めない。
 *
 * @throws 残りが `units` に足りない場合（VericertsError、code `2001`）。
 */
export function assertResolutionWorkRemaining(
  budget: ResolutionWorkBudget | undefined,
  units: number,
): void {
  if (budget !== undefined && (units > budget.remaining || budget.remainingBodyLength <= 0)) {
    throw new VericertsError(ErrorCodes.INVALID_DID, {
      context: { reason: 'resolution_work_limit' },
    });
  }
}

/**
 * 仕事量を消費する。`budget` が無い呼び出し（スコープ外の単独解決）は計上しない。
 * 残りが足りなければ何も消費せず `INVALID_DID`（`context.reason: 'resolution_work_limit'`）で拒否する。
 *
 * @throws 残りが `units` に足りない場合（VericertsError、code `2001`）。
 */
export function consumeResolutionWork(
  budget: ResolutionWorkBudget | undefined,
  units: number,
): void {
  if (budget === undefined) {
    return;
  }
  if (units > budget.remaining) {
    throw new VericertsError(ErrorCodes.INVALID_DID, {
      context: { reason: 'resolution_work_limit' },
    });
  }
  budget.remaining -= units;
}
