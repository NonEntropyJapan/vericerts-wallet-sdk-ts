/**
 * DIF Presentation Exchange v2 の Presentation Submission 構築と検証。
 *
 * 本モジュールは選択済みクレデンシャルから Submission を組み立てる **純粋関数** を提供する
 * （VP Token の署名・暗号化は `auth/oid4vp/oid4vp.ts` の責務であり、本モジュールは伴わない）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` にクレーム値や VC 本文を含めない。
 */

import type { QueryableCredential } from '../auth/dcql/dcql.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import { nonObjectPrototypeProperty, ownProperty } from '../prototype-safety/own-property.js';
import type { PresentationDefinition } from './definition.js';

/** Submission の単一エントリ。 */
export interface DescriptorMap {
  /** 対応する `InputDescriptor.id`。 */
  readonly id: string;
  /** 提示するクレデンシャルの format（`jwt_vc_json` / `dc+sd-jwt` / `vc+sd-jwt` / `ldp_vc`）。 */
  readonly format: string;
  /** VP Token 内のパス（例: `$.verifiableCredential[0]`）。 */
  readonly path: string;
  /** ネストされた VC 参照。 */
  readonly path_nested?: DescriptorMap;
}

/** Presentation Submission。 */
export interface PresentationSubmission {
  /** この Submission の識別子。 */
  readonly id: string;
  /** 対応する `PresentationDefinition.id`。 */
  readonly definition_id: string;
  /** Input Descriptor と提示 VC の対応表。 */
  readonly descriptor_map: readonly DescriptorMap[];
}

/** `buildPresentationSubmission` のオプション。 */
export interface BuildPresentationSubmissionOptions {
  /** submission ID 生成（テスト注入用）。省略時は `crypto.randomUUID()`。 */
  readonly generateId?: () => string;
}

/**
 * 選択済みクレデンシャルから Presentation Submission を組み立てる。
 *
 * `selectedVCs` は `pd.input_descriptors` と**同じ長さ・同じ並び順**で、`selectedVCs[i]` が
 * `input_descriptors[i]` を満たす選択済みクレデンシャルであることを前提とする。
 *
 * 各 `descriptor_map` エントリの `format` は対応する `QueryableCredential` から取得する。
 *
 * @param pd パース済み Presentation Definition。
 * @param selectedVCs `pd.input_descriptors` と同順・同数の選択済みクレデンシャル。
 * @param options `generateId`（submission ID 生成の差し替えシーム）。
 * @returns 組み立てた `PresentationSubmission`。
 * @throws 件数が `input_descriptors` と一致しない場合（VericertsError、code `8035`）。
 */
export function buildPresentationSubmission(
  pd: PresentationDefinition,
  selectedVCs: readonly QueryableCredential[],
  options?: BuildPresentationSubmissionOptions,
): PresentationSubmission {
  if (selectedVCs.length !== pd.input_descriptors.length) {
    throw new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED, {
      context: { reason: 'input_descriptor_count_mismatch' },
    });
  }

  const generateId =
    (options === undefined
      ? undefined
      : nonObjectPrototypeProperty<() => string>(options, 'generateId')) ??
    (() => crypto.randomUUID());
  const descriptorMap: DescriptorMap[] = [];
  for (const [index, descriptor] of pd.input_descriptors.entries()) {
    const credential = selectedVCs[index];
    if (credential === undefined) {
      // 長さは一致していても疎配列（穴）なら要素が欠ける。断定キャストで隠さず fail-closed にする。
      throw new VericertsError(ErrorCodes.PRESENTATION_SUBMIT_FAILED, {
        context: { reason: 'missing_selected_credential', index },
      });
    }
    descriptorMap.push({
      id: descriptor.id,
      format: credential.format,
      path: `$.verifiableCredential[${index}]`,
    });
  }

  return {
    id: generateId(),
    definition_id: pd.id,
    descriptor_map: descriptorMap,
  };
}

/**
 * Presentation Submission が Presentation Definition と整合するか検査する。
 *
 * 検査内容:
 * - `definition_id` が `pd.id` と一致すること。
 * - `descriptor_map` の各 `id` が `pd.input_descriptors` に存在すること。
 * - `pd.input_descriptors` の全 id が `descriptor_map` でカバーされていること。
 * - `descriptor_map` 内で `id` が重複していないこと。
 *
 * 提示できるかを呼び出し側が判断できるように、結果を真偽値で返す。
 *
 * @param submission 検査対象の Submission。
 * @param pd 対応する Presentation Definition。
 * @returns 整合していれば `true`。
 */
export function validatePresentationSubmission(
  submission: PresentationSubmission,
  pd: PresentationDefinition,
): boolean {
  // `submission` はウォレット（非信頼）から受け取った JSON で、形は型に従わない。素の読みだと
  // 形不正で `TypeError` が漏れ（契約は例外を投げず `false`）、必須キーを欠く `{}` が
  // `Object.prototype.definition_id` / `descriptor_map` の汚染値で「整合 OK」になる。キーは own 限定で読み、
  // 形が合わなければすべて `false`（fail-closed）にする。
  if (typeof submission !== 'object' || submission === null) {
    return false;
  }
  if (ownProperty<unknown>(submission, 'definition_id') !== pd.id) {
    return false;
  }
  const descriptorMap = ownProperty<unknown>(submission, 'descriptor_map');
  if (!Array.isArray(descriptorMap)) {
    return false;
  }

  const descriptorIds = new Set<string>();
  for (const entry of descriptorMap as readonly unknown[]) {
    const id =
      typeof entry === 'object' && entry !== null ? ownProperty<unknown>(entry, 'id') : undefined;
    if (typeof id !== 'string' || descriptorIds.has(id)) {
      return false;
    }
    descriptorIds.add(id);
  }

  const definitionIds = new Set(pd.input_descriptors.map((descriptor) => descriptor.id));
  if (descriptorIds.size !== definitionIds.size) {
    return false;
  }
  for (const id of definitionIds) {
    if (!descriptorIds.has(id)) {
      return false;
    }
  }
  return true;
}
