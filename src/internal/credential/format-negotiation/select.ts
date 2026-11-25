/**
 * VC フォーマット選択アルゴリズム。
 *
 * Verifier の `vp_formats` 要求に対し、保持候補 VC をスコアリングして最適なものを選ぶ純粋関数群。
 * ネットワーク・署名検証・VP 構築は伴わない（それらは呼び出し側 / `multi-format.ts` の責務）。
 *
 * 実装は責務分離のため以下へ分割し、本モジュールは `selectBestVC` の組み立てと公開 API の入口を
 * 一本化する（`Linterly` の行数上限対応）:
 * - `constraints.ts`: 署名スイート制約の充足判定（ダウングレード拒否）。
 * - `scoring.ts`: 合成スコア計算（フォーマット優先度・alg 優先度・プライバシー・期限）。
 * - `compare.ts`: 候補比較・相関回避シャッフル・既定タイブレーク。
 * - `coverage.ts`: 被覆判定（`canFulfillFormats`。本モジュールが再エクスポート）。
 *
 * スコアリング:
 *   1. フォーマット優先度（Verifier 要求の並び順、先頭が最優先）
 *   2. 署名アルゴリズム優先度（`alg` の先頭が最優先）
 *   3. プライバシー優先度（Unlinkable > SD > Full Disclosure）
 *   4. 期限（長期有効 > 短期有効）
 *   5. 鍵バインディング（保持している > 判定不能 > 保持していない）
 *   6. ユーザー優先度（お気に入り指定 > 直近の利用日時）
 * 同点時タイブレーク: 新しい `issuanceDate` が勝ち。それでも同点なら乱数で選ぶ（相関回避）。
 *
 * セキュリティ上の注意:
 * - 署名スイートの強度降格（ダウングレード）は要求 `alg` 外の VC を候補から除外することで拒否する。
 * - 例外メッセージ・`context` にクレーム値や VC 本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { WorkBudget } from '../../primitives/work-budget.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { compareCandidates, defaultRandomTiebreak, shuffle } from './compare.js';
import { satisfiesRequirement } from './constraints.js';
import type { NegotiableCredential, VCSelection, VpFormatRequirement } from './types.js';
import { chargeFormatWork, createFormatWorkBudget } from './work.js';

export { canFulfillFormats } from './coverage.js';

/** `selectBestVC` のオプション。 */
export interface SelectBestVCOptions {
  /** 完全同点時のタイブレーク乱数（0〜1）。テスト決定化用。既定は暗号乱数。 */
  readonly randomTiebreak?: () => number;
  /** この選択が対応する descriptor / DCQL 要件 ID。結果の `descriptorId` に設定する。 */
  readonly descriptorId?: string;
  /**
   * 仕事量予算（{@link createFormatWorkBudget}）。複数の descriptor を評価する呼び出し側（`evaluateFormatCapability`）は
   * 1 つを共有して渡す。省略時は呼び出しごとに新しい予算。超過は 3050（`format_work_budget_exceeded`）。
   */
  readonly budget?: WorkBudget;
}

/**
 * Verifier 要求に対して最適な候補 VC を 1 件選択する。
 *
 * 前提: `candidates` は既にクレーム要件（DCQL / PEx）を満たすものだけに絞られていること
 * （クレーム一致は `matcher.ts` / `dcql.ts` の責務。本関数はフォーマット・alg・プライバシー・
 * 期限のみで選ぶ）。フォーマット / `alg` 制約を満たさない候補は本関数内で除外する。
 *
 * @param requested Verifier の `vp_formats` 要求（挿入順が優先度）。
 * @param candidates クレーム要件を満たす正規化候補 VC。
 * @param opts タイブレーク乱数・descriptorId。
 * @returns 選択結果（`chosen` + 最大 2 件の `alternatives`）。
 * @throws 要求を満たす候補が 1 つもない場合（VericertsError、code `3050`）。
 */
export function selectBestVC(
  requested: VpFormatRequirement,
  candidates: readonly NegotiableCredential[],
  opts?: SelectBestVCOptions,
): VCSelection {
  // opts は own 限定（`Object.prototype.budget` の汚染で仕事量予算が差し替わり上限が緩むのを防ぐ）。
  const ownOpts = opts ?? {};
  const randomTiebreak =
    nonObjectPrototypeProperty<() => number>(ownOpts, 'randomTiebreak') ?? defaultRandomTiebreak;
  const budget =
    nonObjectPrototypeProperty<WorkBudget>(ownOpts, 'budget') ?? createFormatWorkBudget();
  const descriptorId = ownProperty<string>(ownOpts, 'descriptorId');
  const eligible = candidates.filter((vc) => satisfiesRequirement(vc, requested, budget));
  if (eligible.length === 0) {
    const requestedFormats = Object.keys(requested);
    chargeFormatWork(budget, requestedFormats.length);
    throw new VericertsError(ErrorCodes.VP_FORMATS_NOT_SUPPORTED, {
      context: {
        requestedFormats,
        candidateCount: candidates.length,
      },
    });
  }
  // 完全同点候補の相関回避: 安定ソート前にシャッフルし、compareCandidates が
  // 0 を返す同点はシャッフル順（＝ランダム）で確定させる。
  const shuffled = shuffle(eligible, randomTiebreak);
  const sorted = shuffled.sort((a, b) => compareCandidates(a, b, requested, budget));
  // eligible.length >= 1 を上で保証済みのため sorted[0] は必ず存在する。
  const chosen = sorted[0] as NegotiableCredential;
  return {
    ...(descriptorId !== undefined ? { descriptorId } : {}),
    chosen,
    alternatives: sorted.slice(1, 3),
  };
}
