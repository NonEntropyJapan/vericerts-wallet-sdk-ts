/**
 * Verifier の提示要求と Wallet の保有 VC から、提示できるフォーマットを判定する。
 *
 * Wallet 保持候補 VC と Verifier の `vp_formats` 要求を突き合わせ、descriptor 毎の選択結果と
 * 被覆状況・警告を返す。Verifier が複数フォーマットを並行要求（Multi-format VP）した場合は
 * descriptor 毎に独立して最適 VC を選ぶ。
 *
 * フォールバックの条件:
 * - 全 descriptor を満たせない場合でも例外にせず、`fullyCovered=false` と満たせなかった
 *   descriptor を返す（部分被覆を UI で明示するため）。個別選択の失敗（3050）はその descriptor を
 *   `unmatchedDescriptors` に積み、警告を付す。
 * - PEx `constraints.limit_disclosure: "required"` は、選択的開示
 *   対応の候補のみに絞ってから選択する。絞り込みの結果候補が尽きた場合はその descriptor を
 *   `unmatchedDescriptors` に積む（VP 不送信。エラーコードは発行しない — Verifier に送信しない
 *   Wallet 内部判断のため）。
 *
 * セキュリティ上の注意:
 * - 警告メッセージにクレーム値や VC 本文を含めない。
 */

import { VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../../prototype-safety/own-property.js';
import { canFulfillFormats, selectBestVC } from './select.js';
import {
  type FormatCapabilityResult,
  isSelectiveDisclosureCapable,
  type LimitDisclosure,
  type NegotiableCredential,
  type VCSelection,
  type VpFormatRequirement,
} from './types.js';
import { chargeFormatWork, createFormatWorkBudget } from './work.js';

/** 1 つの descriptor（input_descriptor / DCQL credential 要件）のフォーマット要求。 */
export interface FormatDescriptor {
  /** descriptor の一意 ID。 */
  readonly id: string;
  /** この descriptor が受け入れる `vp_formats` 要求。 */
  readonly vpFormats: VpFormatRequirement;
  /**
   * この descriptor のクレーム要件を満たす候補 VC。呼び出し側が DCQL / PEx で事前に絞る。
   * 空配列の場合は要件を満たす VC が存在しないとみなす。
   */
  readonly candidates: readonly NegotiableCredential[];
  /**
   * PEx `input_descriptor.constraints.limit_disclosure`。
   * `"required"` の場合、選択的開示に対応しない候補（`isSelectiveDisclosureCapable` が `false`）は
   * 除外してから選択する。省略時は制約なし。
   */
  readonly limitDisclosure?: LimitDisclosure;
}

/** `evaluateFormatCapability` のオプション。 */
export interface EvaluateFormatCapabilityOptions {
  /** 完全同点時のタイブレーク乱数（0〜1）。テスト決定化用。 */
  readonly randomTiebreak?: () => number;
}

/**
 * Verifier の各 descriptor に対し保持 VC のフォーマット適合性を評価する。
 *
 * @param descriptors descriptor 毎のフォーマット要求 + 候補 VC。
 * @param opts タイブレーク乱数。
 * @returns 被覆状況・descriptor 毎の選択・満たせなかった descriptor・警告。
 */
export function evaluateFormatCapability(
  descriptors: readonly FormatDescriptor[],
  opts?: EvaluateFormatCapabilityOptions,
): FormatCapabilityResult {
  const selections: VCSelection[] = [];
  const unmatchedDescriptors: string[] = [];
  const warnings: string[] = [];
  // 1 回の評価全体（全 descriptor × 候補 × 制約要素）で共有する仕事量予算。
  const budget = createFormatWorkBudget();

  for (const descriptor of descriptors) {
    // descriptor 1 件の評価の固定費と、`limit_disclosure` 絞り込み（候補全件の走査）を入口で計上する。
    // 記述子数 D は個別の上限が無いため、共有 `vpFormats` を指す小さな descriptor を並べた増幅もここで縛る。
    chargeFormatWork(budget, 1 + descriptor.candidates.length);
    // `limit_disclosure: required` は選択的開示非対応の候補を選択対象から外す。絞り込みは
    // 被覆判定・選択の両方より前段で行い、以降は絞り込み後の候補集合を一貫して用いる。
    // `limitDisclosure` は呼び出し側が省略しうるので own 限定で読む（鎖読みは `Object.prototype` の汚染値で絞り込みが変わる）。
    const limitDisclosureRequired =
      ownProperty<unknown>(descriptor, 'limitDisclosure') === 'required';
    const eligibleCandidates = limitDisclosureRequired
      ? descriptor.candidates.filter(isSelectiveDisclosureCapable)
      : descriptor.candidates;
    const blockedByLimitDisclosure =
      limitDisclosureRequired &&
      descriptor.candidates.length > 0 &&
      eligibleCandidates.length === 0;

    // 保持候補で要求フォーマットをどこまで満たせるかを先に把握し、部分被覆を警告に反映する。
    const coverage = canFulfillFormats(descriptor.vpFormats, eligibleCandidates, budget);
    if (!coverage.fullyCovered && coverage.matchedFormats.length > 0) {
      warnings.push(
        `descriptor "${descriptor.id}": 一部のフォーマットのみ対応可能（未対応: ${coverage.unmatchedFormats.join(', ')}）`,
      );
    }

    const randomTiebreak =
      opts === undefined
        ? undefined
        : nonObjectPrototypeProperty<() => number>(opts, 'randomTiebreak');
    try {
      const selection = selectBestVC(descriptor.vpFormats, eligibleCandidates, {
        descriptorId: descriptor.id,
        budget,
        ...(randomTiebreak !== undefined ? { randomTiebreak } : {}),
      });
      selections.push(selection);
    } catch (error) {
      // 仕事量予算の超過は「この descriptor が満たせない」ではなく評価全体の拒否（fail-closed）。
      if (error instanceof VericertsError && !budget.exhausted) {
        unmatchedDescriptors.push(descriptor.id);
        warnings.push(
          blockedByLimitDisclosure
            ? `descriptor "${descriptor.id}": limit_disclosure=required だが選択的開示に対応する VC がないため VP を送信しません`
            : `descriptor "${descriptor.id}": 要求 VP フォーマットに対応できません`,
        );
        continue;
      }
      throw error;
    }
  }

  return {
    fullyCovered: unmatchedDescriptors.length === 0,
    selections,
    unmatchedDescriptors,
    warnings,
  };
}
