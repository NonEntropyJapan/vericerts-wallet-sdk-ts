/**
 * Presentation Definition の件数上限。
 *
 * 記述子 D 件 × 保有 VC H 件ぶんの `CredentialMatch` を評価が確保するため、DCQL（
 * `MAX_DCQL_CREDENTIALS`）と同じく件数は要素を評価する前に縛る。
 */

import { rejectOversized } from '../auth/dcql/limits.js';
import { ErrorCodes, VericertsError } from '../errors.js';

/**
 * `input_descriptors` の最大件数。1 MiB の PD に `fields: []`（全 VC に一致）の記述子を 2 万件並べ、
 * 保有 VC 2,000 件で一致 4,000 万件・RSS 約 5 GB を確保させられた。実在の PD は 1〜数件のため
 * 桁違いに大きい値（`MAX_DCQL_CREDENTIALS` と同値）。
 */
export const MAX_INPUT_DESCRIPTORS = 64;

/**
 * 1 回の評価が確保する `CredentialMatch` の最大件数。記述子数の上限（{@link MAX_INPUT_DESCRIPTORS}）を守った PD でも、
 * 保有 VC 数に比例して一致が増えるため、結果配列そのものを縛る。超過は一部を切り捨てずに 8030 で拒否する（fail-closed）。
 */
export const MAX_PEX_MATCHES = 100_000;

/**
 * `field.filter.enum` の最大件数。評価は要素 1 件ごとに `deepEqual` を呼ぶため、1 MiB の PD に
 * 数十万件の要素を並べると、走査量予算が尽きるまで保有 VC ごとに同じ列を走査できた。実在の `enum` は数件〜数十件で、
 * 桁違いに大きい値。評価側の計上（要素 1 件 = 走査量 1 単位以上）は件数上限とは独立に常に効く。
 */
export const MAX_FILTER_ENUM_LENGTH = 1_024;

/** 記述子数が `MAX_INPUT_DESCRIPTORS` を超えるなら 8030（`too_many_input_descriptors`）。 */
export function rejectTooManyInputDescriptors(descriptors: unknown): void {
  rejectOversized(descriptors, MAX_INPUT_DESCRIPTORS, 'too_many_input_descriptors');
}

/**
 * 評価結果の件数が `MAX_PEX_MATCHES` に達していれば 8030（`too_many_matches`）。次の 1 件を確保する前に呼ぶ。
 */
export function rejectTooManyMatches(currentCount: number): void {
  if (currentCount >= MAX_PEX_MATCHES) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'too_many_matches' },
    });
  }
}
