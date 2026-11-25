/**
 * 攻撃者が件数と長さを選べる入力の「合計量」上限（件数 × 長さ）と、走査量の共通予算。
 *
 * 個別の上限（件数だけ・長さだけ）は、もう一方の軸へ迂回されて積（O(N×M)）になる
 * （Offer の id 件数 × Metadata の `type` 長、AS 件数 × 末尾スラッシュ長、
 * x5c 件数 × 証明書ごとのキー長）。本ヘルパは次の 2 つを 1 か所に置く:
 *
 * - {@link isBoundedStringList}: 件数・1 要素長・合計長を**すべて**課す。件数は走査の前に O(1) で
 *   判定するため、超過入力でも走査量が上限を超えない。
 * - {@link WorkMeter}: 複数の入力・複数の呼び出しにまたがって走査した要素数を数える共有予算
 *   （`spent` は決定的なカウンタで、テストが実時間を使わずに pin できる）。
 */

/** 文字列配列に課す 3 つの上限。 */
export interface StringListLimits {
  /** 要素数の上限（走査の前に判定する）。 */
  readonly maxCount: number;
  /** 1 要素の長さ（UTF-16 コード単位）の上限。 */
  readonly maxItemLength: number;
  /** 全要素の長さの合計の上限。 */
  readonly maxTotalLength: number;
}

/**
 * `list` が件数・1 要素長・合計長の上限内の文字列だけから成るか。
 *
 * @param list 検査対象（攻撃者が長さを決められる配列）。
 * @param limits 上限。
 * @param accept 各要素に追加で課す述語（例: 非空）。省略時は文字列であれば良い。
 * @returns すべて満たせば true（型ガード）。要素数が上限超過なら要素に触れず false。
 */
export function isBoundedStringList(
  list: readonly unknown[],
  limits: StringListLimits,
  accept?: (value: string) => boolean,
): list is readonly string[] {
  if (list.length > limits.maxCount) {
    return false;
  }
  let total = 0;
  for (const entry of list) {
    if (typeof entry !== 'string' || entry.length > limits.maxItemLength) {
      return false;
    }
    total += entry.length;
    if (total > limits.maxTotalLength || (accept !== undefined && !accept(entry))) {
      return false;
    }
  }
  return true;
}

/** 走査量の共有予算。`spent` は消費済みの単位数（決定的に pin できる計数）。 */
export interface WorkMeter {
  remaining: number;
  spent: number;
}

/** 新しい予算を作る。 */
export function newWorkMeter(limit: number): WorkMeter {
  return { remaining: limit, spent: 0 };
}

/**
 * `units` を予算から消費する。足りなければ**何も消費せず** false を返す（呼び出し側は走査を始めない）。
 */
export function spendWork(meter: WorkMeter, units: number): boolean {
  if (units > meter.remaining) {
    return false;
  }
  meter.remaining -= units;
  meter.spent += units;
  return true;
}
