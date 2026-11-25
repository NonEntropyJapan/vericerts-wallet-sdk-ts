/**
 * VC 選択のスコアリング。
 *
 * `select.ts` の合成スコア計算を切り出す（`Linterly` の行数上限対応でのファイル分割。
 * 責務・公開 API に変更はない）。
 */

import { parseIsoDateTimeMs } from '../../cache/iso-datetime.js';
import type { WorkBudget } from '../../primitives/work-budget.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import {
  formatConstraintOf,
  type NegotiableCredential,
  PRIVACY_TIER,
  type VpFormatRequirement,
} from './types.js';
import { chargeFormatWork } from './work.js';

/** スコア合成の桁重み。上位要素が必ず下位に優先する。 */
const WEIGHT_FORMAT = 1_000_000;
const WEIGHT_ALG = 10_000;
const WEIGHT_PRIVACY = 100;

/**
 * フォーマット優先度スコア。
 * 要求の先頭ほど高い。要求に含まれないフォーマットは 0。
 */
function formatPriority(
  format: string,
  requested: VpFormatRequirement,
  budget: WorkBudget,
): number {
  const keys = Object.keys(requested);
  chargeFormatWork(budget, keys.length);
  const idx = keys.indexOf(format);
  return idx === -1 ? 0 : keys.length - idx;
}

/**
 * 署名アルゴリズム優先度スコア。
 * 要求 `alg` リストの先頭ほど高い。制約に `alg` がない場合は中立（0）。
 */
function algPriority(
  alg: string | undefined,
  requestedAlg: readonly string[] | undefined,
  budget: WorkBudget,
): number {
  if (requestedAlg === undefined || requestedAlg.length === 0) {
    return 0;
  }
  if (alg === undefined) {
    return 0;
  }
  chargeFormatWork(budget, requestedAlg.length);
  const idx = requestedAlg.indexOf(alg);
  return idx === -1 ? 0 : requestedAlg.length - idx;
}

/** プライバシースコア。未知フォーマットは 0。 */
function privacyScore(format: string): number {
  return PRIVACY_TIER[format] ?? 0;
}

/**
 * 期限スコア。有効期限が遠いほど高い。
 * `expirationDate` 未設定（無期限）は最大扱い。パース不能は 0。
 */
export function freshnessScore(expirationDate: string | undefined): number {
  if (expirationDate === undefined) {
    return Number.MAX_SAFE_INTEGER;
  }
  const ms = parseIsoDateTimeMs(expirationDate);
  return Number.isNaN(ms) ? 0 : ms;
}

/**
 * プライバシー貢献度。フォーマット既定の tier を基準に、SD 対応の明示指定で上書き調整する。
 * SD 非対応と明示された場合はプライバシーを Full Disclosure 相当（30）に落とす。
 */
function privacyContribution(vc: NegotiableCredential): number {
  const base = privacyScore(vc.format);
  if (ownProperty<boolean>(vc, 'supportsSelectiveDisclosure') === false && base > 30) {
    return 30;
  }
  return base;
}

/**
 * 合成スコアを計算する。上位要素が下位を必ず支配するよう桁で分離する。
 *
 * 要求フォーマットのキー列挙（`Object.keys`）と `alg` の `indexOf` は要求の大きさに比例するため、
 * 呼び出しごとに予算へ計上する。選択（`selectBestVC`）は候補ごとに 1 回だけ計算して使い回す。
 */
export function scoreCredential(
  vc: NegotiableCredential,
  requested: VpFormatRequirement,
  budget: WorkBudget,
): number {
  chargeFormatWork(budget, 1);
  const constraint = formatConstraintOf(requested, vc.format);
  return (
    formatPriority(vc.format, requested, budget) * WEIGHT_FORMAT +
    algPriority(ownProperty<string>(vc, 'alg'), constraint?.alg, budget) * WEIGHT_ALG +
    privacyContribution(vc) * WEIGHT_PRIVACY
  );
}
