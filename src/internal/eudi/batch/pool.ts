/**
 * Batch Pool の消費追跡と期限切れパージ。
 *
 * 純粋関数として実装し、入力プール配列を変更せず新しい配列を返す（immutable）。
 * 実際の永続化（IndexedDB）・WSCD 鍵削除は呼び出し側 facade が担う。
 */

import type { BatchPoolItem, ConsumeResult, PurgeResult } from './types.js';

/** 有効な（未使用かつ未期限切れ）VC か判定する。 */
function isUsable(item: BatchPoolItem, now: number): boolean {
  return !item.used && item.expiresAt > now;
}

/**
 * 有効な未使用 VC の残量を数える（`used=false AND exp>now`）。
 */
export function countAvailable(pool: readonly BatchPoolItem[], now: number): number {
  let count = 0;
  for (const item of pool) {
    if (isUsable(item, now)) {
      count += 1;
    }
  }
  return count;
}

/**
 * VP 提示のために未使用 VC を 1 個消費する。
 *
 * 最も早く期限切れになる有効 VC を優先選択し（在庫回転で失効ロスを減らす）、
 * その VC を `used=true` に更新したプールを返す。同一 VC が複数 RP に提示される
 * ことを防ぐため、選択は 1 個のみで即座に消費済みへ遷移させる。
 *
 * @param pool 現在のプール。変更しない。
 * @param now  基準時刻（epoch ミリ秒）。
 * @param rp   消費先 RP 識別子。監査用に `consumedRp` へ記録する。
 * @returns 消費結果。有効な VC が無ければ `consumed=false`・プールは不変。
 */
export function consumeCredential(
  pool: readonly BatchPoolItem[],
  now: number,
  rp: string,
): ConsumeResult {
  let target: BatchPoolItem | undefined;
  for (const item of pool) {
    if (!isUsable(item, now)) {
      continue;
    }
    if (target === undefined || item.expiresAt < target.expiresAt) {
      target = item;
    }
  }

  if (target === undefined) {
    return { consumed: false, pool };
  }

  const consumedItem: BatchPoolItem = {
    ...target,
    used: true,
    consumedAt: now,
    consumedRp: rp,
  };
  const nextPool = pool.map((item) => (item.id === target.id ? consumedItem : item));

  return { consumed: true, item: consumedItem, pool: nextPool };
}

/**
 * 期限切れ VC をプールから除去する。
 *
 * `expiresAt <= now` の VC を削除し、削除対象の WSCD 鍵ハンドルを返す
 * （呼び出し側が `WSCD.delete(keyHandle)` で秘密鍵を破棄する）。
 *
 * @param pool 現在のプール。変更しない。
 * @param now  基準時刻（epoch ミリ秒）。
 * @returns パージ後のプールと削除した鍵ハンドル一覧。
 */
export function purgeExpired(pool: readonly BatchPoolItem[], now: number): PurgeResult {
  const kept: BatchPoolItem[] = [];
  const removedKeyHandles: string[] = [];
  for (const item of pool) {
    if (item.expiresAt <= now) {
      removedKeyHandles.push(item.keyHandle);
    } else {
      kept.push(item);
    }
  }
  return { pool: kept, removedKeyHandles };
}
