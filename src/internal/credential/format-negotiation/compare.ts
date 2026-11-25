/**
 * VC 候補の比較・相関回避シャッフル。
 *
 * `select.ts` の並び替えロジックを切り出す（`Linterly` の行数上限対応でのファイル分割。
 * 責務・公開 API に変更はない）。
 */

import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import type { WorkBudget } from '../../primitives/work-budget.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { freshnessScore, scoreCredential } from './scoring.js';
import type { NegotiableCredential, VpFormatRequirement } from './types.js';
import { chargeFormatWork } from './work.js';

/**
 * 鍵バインディング可用性の順位。
 * `hasBoundKey === true`（cnf 所有鍵を保持）を最上位、`false`（保持していないと判明）を最下位とし、
 * `undefined`（cnf なし、または未判定）はその中間の中立値として扱う。
 * こうすることで「保持していないと判明した VC」だけを積極的に後退させ、判定情報が無い既存の
 * 候補（`hasBoundKey` 未設定）同士の比較は 0（同点）になる。
 */
function keyBindingAvailabilityRank(vc: NegotiableCredential): number {
  if (ownProperty<boolean>(vc, 'hasBoundKey') === true) {
    return 1;
  }
  if (ownProperty<boolean>(vc, 'hasBoundKey') === false) {
    return -1;
  }
  return 0;
}

/**
 * 鍵バインディング可用性の比較。
 * cnf 所有鍵をウォレットが保持している候補を、保持していないと判明した候補より優先する。
 *
 * 戻り値 < 0 なら a が優先。`compareCandidates` と同じ符号規約。
 */
function compareKeyBindingAvailability(a: NegotiableCredential, b: NegotiableCredential): number {
  return keyBindingAvailabilityRank(b) - keyBindingAvailabilityRank(a);
}

/**
 * ユーザー優先度の比較。
 * お気に入り指定（`isFavorite === true`）を最優先し、次点で `lastUsedAt` が新しいものを優先する。
 * どちらも未指定・同値の候補間は 0（同点）を返し、呼び出し側のタイブレークに委ねる。
 *
 * 戻り値 < 0 なら a が優先。`compareCandidates` と同じ符号規約。
 */
function compareUserPreference(a: NegotiableCredential, b: NegotiableCredential): number {
  const favoriteA = ownProperty<boolean>(a, 'isFavorite') === true ? 1 : 0;
  const favoriteB = ownProperty<boolean>(b, 'isFavorite') === true ? 1 : 0;
  if (favoriteA !== favoriteB) {
    return favoriteB - favoriteA;
  }
  const usedA = parseIsoDateTimeMs(ownProperty<string>(a, 'lastUsedAt'));
  const usedB = parseIsoDateTimeMs(ownProperty<string>(b, 'lastUsedAt'));
  const normA = Number.isNaN(usedA) ? -Infinity : usedA;
  const normB = Number.isNaN(usedB) ? -Infinity : usedB;
  if (normA === normB) {
    return 0;
  }
  return normB - normA > 0 ? 1 : -1;
}

/**
 * 2 候補の優先順位を比較する（降順ソート用比較関数）。
 * 戻り値 < 0 なら a が優先。合成スコア → 期限 → 鍵バインディング可用性 → ユーザー優先度 →
 * issuanceDate の順で決定する。
 *
 * 完全同点（全要素が等しい）の場合は 0 を返す。完全同点のタイブレーク（相関回避の
 * ランダム選択）は、比較関数の中では安定ソート挙動に依存して不定になるため、`selectBestVC` 側で
 * 事前シャッフルにより実現する。
 */
export function compareCandidates(
  a: NegotiableCredential,
  b: NegotiableCredential,
  requested: VpFormatRequirement,
  budget: WorkBudget,
): number {
  // 比較 1 回の固定費。スコア計算（要求の大きさに比例）は `scoreCredential` が計上する。
  chargeFormatWork(budget, 1);
  const scoreDiff = scoreCredential(b, requested, budget) - scoreCredential(a, requested, budget);
  if (scoreDiff !== 0) {
    return scoreDiff;
  }
  // 期限（長期有効優先）。
  const freshDiff =
    freshnessScore(ownProperty<string>(b, 'expirationDate')) -
    freshnessScore(ownProperty<string>(a, 'expirationDate'));
  if (freshDiff !== 0) {
    return freshDiff > 0 ? 1 : -1;
  }
  // 鍵バインディング可用性（cnf 所有鍵が利用可能）。
  const keyBindingDiff = compareKeyBindingAvailability(a, b);
  if (keyBindingDiff !== 0) {
    return keyBindingDiff;
  }
  // ユーザー優先度（お気に入り > 直近の利用日時）。
  const prefDiff = compareUserPreference(a, b);
  if (prefDiff !== 0) {
    return prefDiff;
  }
  // issuanceDate が新しい方を優先する。
  const issuedA = parseIsoDateTimeMs(ownProperty<string>(a, 'issuanceDate'));
  const issuedB = parseIsoDateTimeMs(ownProperty<string>(b, 'issuanceDate'));
  if (!Number.isNaN(issuedA) || !Number.isNaN(issuedB)) {
    const normA = Number.isNaN(issuedA) ? -Infinity : issuedA;
    const normB = Number.isNaN(issuedB) ? -Infinity : issuedB;
    if (normA !== normB) {
      return normB - normA > 0 ? 1 : -1;
    }
  }
  // 完全同点。呼び出し側の事前シャッフル順を尊重するため 0 を返す。
  return 0;
}

/**
 * Fisher–Yates シャッフル（相関回避のための事前ランダム化）。
 * `random` は [0,1) の乱数を返す関数（テスト決定化用に注入）。
 */
export function shuffle<T>(items: readonly T[], random: () => number): T[] {
  const arr = [...items];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    const tmp = arr[i] as T;
    arr[i] = arr[j] as T;
    arr[j] = tmp;
  }
  return arr;
}

/** 暗号乱数ベースの既定タイブレーク（[0,1)）。 */
export function defaultRandomTiebreak(): number {
  // crypto.randomUUID() は browser / node / bun いずれでも利用可能。
  // v4 UUID の先頭 8 hex 桁（ハイフン前）はバージョン/バリアントビットの影響を受けない
  // 完全ランダム値なので、それを [0,1) の一様乱数として利用する。
  const uuid = crypto.randomUUID();
  const firstGroup = uuid.slice(0, 8);
  return parseInt(firstGroup, 16) / 0x1_0000_0000;
}
