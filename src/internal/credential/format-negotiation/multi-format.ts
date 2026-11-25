/**
 * 複数形式同時提示（Multi-format VP）。
 *
 * Verifier が複数フォーマットを並行要求し、`input_descriptor` ごとに異なるフォーマットを
 * 受け入れる場合に、選択済み VC 群から OID4VP の Multi-format VP Token を組み立てる。
 *
 * 実装制約:
 * - 最大 3 形式まで（UX 許容範囲）。超過は `VP_FORMATS_NOT_SUPPORTED`（3050）。
 * - 全 VP で同一の `nonce` を使用する。
 * - `presentation_submission.descriptor_map` の `path_nested` でフォーマット毎の位置を示す。
 * - 監査ログ: 各 VP のハッシュを個別記録する（呼び出し側の `recordAudit` に委譲）。
 *
 * 本モジュールは各フォーマット用の VP 文字列（署名済み）を生成する処理を DI で受け取り、
 * それらを 1 つの Multi-format VP Token へ束ねる純粋な組み立てロジックを提供する。署名鍵は
 * 呼び出し側の `buildVpFor` に閉じ込め、本関数に生の秘密鍵を渡さない。
 * VP 文字列そのもの・クレーム値は監査ログに渡さず、SHA-256 ハッシュのみを渡す。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { nonObjectPrototypeProperty } from '../../prototype-safety/own-property.js';
import { MAX_MULTI_FORMAT_COUNT, type VCSelection } from './types.js';

/** PEx v2 presentation_submission の descriptor_map エントリ（path_nested 対応）。 */
export interface DescriptorMapEntry {
  /** DCQL / PEx の input_descriptor ID。 */
  readonly id: string;
  /** この descriptor のフォーマット。 */
  readonly format: string;
  /** vp_token 配列内での位置（`$[n]`）。 */
  readonly path: string;
  /** VP 内 VC の位置を示す入れ子パス。 */
  readonly path_nested?: {
    readonly format: string;
    readonly path: string;
  };
}

/** OID4VP の presentation_submission。 */
export interface PresentationSubmission {
  /** submission の一意 ID。 */
  readonly id: string;
  /** 対応する presentation_definition の ID。 */
  readonly definition_id: string;
  /** descriptor 毎の位置マップ。 */
  readonly descriptor_map: readonly DescriptorMapEntry[];
}

/** Multi-format VP Token。 */
export interface MultiFormatVPToken {
  /** OID4VP: フォーマット毎の独立した VP 文字列の配列。 */
  readonly vp_token: readonly string[];
  /** descriptor_map を持つ presentation_submission。 */
  readonly presentation_submission: PresentationSubmission;
}

/**
 * Multi-format VP 監査ログ 1 エントリ。
 * VP 文字列そのもの・クレーム値は含めず、ハッシュのみを記録する。
 */
export interface MultiFormatAuditEntry {
  /** この VP に対応する DCQL / descriptor 要件の ID。 */
  readonly descriptorId: string;
  /** この VP のフォーマット。 */
  readonly format: string;
  /** VP 文字列の SHA-256 digest（base64url、パディングなし）。 */
  readonly hash: string;
}

/** `buildMultiFormatVP` の依存注入。 */
export interface BuildMultiFormatVPOptions {
  /** presentation_definition の ID（submission に紐付ける）。 */
  readonly definitionId: string;
  /** 全 VP で共有する nonce。 */
  readonly nonce: string;
  /**
   * 1 選択分の VP 文字列を生成する（署名込み）。フォーマット毎の Key Binding
   * （SD-JWT: KB-JWT / mdoc: DeviceAuth）差異はこの実装内で吸収する。
   */
  readonly buildVpFor: (selection: VCSelection, nonce: string) => Promise<string>;
  /**
   * 生成した VP ごとに監査ログへ記録する。VP 文字列の SHA-256 ハッシュのみを渡し、
   * VP 本文やクレーム値は渡さない。
   */
  readonly recordAudit: (entry: MultiFormatAuditEntry) => void | Promise<void>;
  /** submission ID 生成（テスト注入用）。省略時は `crypto.randomUUID()`。 */
  readonly generateId?: () => string;
}

/**
 * 選択済み VC 群から Multi-format VP Token を組み立てる。
 *
 * @param selections descriptor 毎の選択結果（各要素に `descriptorId` が必要）。
 * @param opts nonce / definitionId / VP 生成関数など。
 * @returns vp_token 配列 + descriptor_map を持つ Multi-format VP Token。
 * @throws フォーマット数が 3 を超える場合 / selection が空の場合（VericertsError、code `3050`）。
 */
export async function buildMultiFormatVP(
  selections: readonly VCSelection[],
  opts: BuildMultiFormatVPOptions,
): Promise<MultiFormatVPToken> {
  if (selections.length === 0) {
    throw new VericertsError(ErrorCodes.VP_FORMATS_NOT_SUPPORTED, {
      context: { reason: 'no_selection' },
    });
  }
  const distinctFormats = new Set(selections.map((s) => s.chosen.format));
  if (distinctFormats.size > MAX_MULTI_FORMAT_COUNT) {
    throw new VericertsError(ErrorCodes.VP_FORMATS_NOT_SUPPORTED, {
      context: { reason: 'too_many_formats', count: distinctFormats.size },
    });
  }

  const generateId =
    nonObjectPrototypeProperty<() => string>(opts, 'generateId') ?? (() => crypto.randomUUID());
  const vpTokens: string[] = [];
  const descriptorMap: DescriptorMapEntry[] = [];

  for (let index = 0; index < selections.length; index++) {
    const selection = selections[index] as VCSelection;
    // 全 VP で同一 nonce を使う。
    const vp = await opts.buildVpFor(selection, opts.nonce);
    vpTokens.push(vp);
    const descriptorId = selection.descriptorId ?? `descriptor_${index}`;
    descriptorMap.push({
      id: descriptorId,
      format: selection.chosen.format,
      path: `$[${index}]`,
      path_nested: {
        format: selection.chosen.format,
        path: '$.verifiableCredential[0]',
      },
    });
    // 各 VP のハッシュを個別記録する。VP 本文は渡さずハッシュのみを渡す。
    await opts.recordAudit({
      descriptorId,
      format: selection.chosen.format,
      hash: base64urlnopad.encode(sha256(new TextEncoder().encode(vp))),
    });
  }

  return {
    vp_token: vpTokens,
    presentation_submission: {
      id: generateId(),
      definition_id: opts.definitionId,
      descriptor_map: descriptorMap,
    },
  };
}
