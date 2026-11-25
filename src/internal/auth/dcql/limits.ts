/**
 * DCQL クエリの件数上限。
 *
 * 要求 R 件 × 保有 VC H 件ぶんの `CredentialMatch` を評価が確保するため、件数は要素を評価する前に縛る。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';

/** `parseDcqlQuery` が 8030 に倒す既定の理由（件数が上限を超える DCQL クエリ）。 */
const DCQL_TOO_LARGE = 'dcql_too_large';

/**
 * `dcql_query.credentials` の最大件数。要求 R 件 × 保有 VC H 件ぶんの `CredentialMatch` を評価が確保するため、
 * 1 MiB の query に同形の要求を数万件並べるとメモリが枯渇した。実在の要求は数件のため桁違いに大きい値。
 */
export const MAX_DCQL_CREDENTIALS = 64;

/** 要件 1 件あたりの `claims` の最大件数。 */
export const MAX_DCQL_CLAIMS_PER_CREDENTIAL = 128;

/** `claims[].path` の最大長（辿る深さ）。 */
export const MAX_DCQL_PATH_LENGTH = 16;

/** `claims[].values` / `meta.vct_values` の最大件数。 */
export const MAX_DCQL_ARRAY_LENGTH = 128;

/**
 * 配列が `max` 件を超えるなら 8030（`dcql_too_large`）。配列でない値は何もしない（形の検証は呼び出し側）。
 * 要素を走査・評価する前に件数だけで拒否するため、評価量を入力サイズへ比例させない。
 * PEx の `input_descriptors` 上限も `reason` を替えて共有する。
 */
export function rejectOversized(value: unknown, max: number, reason = DCQL_TOO_LARGE): void {
  if (Array.isArray(value) && value.length > max) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, { context: { reason } });
  }
}

/**
 * `evaluateDcql` が確保する `CredentialMatch` の最大件数。件数上限は要求側だけを縛るため、
 * 要求 R 件 × 保有 VC H 件ぶんの一致は H に比例して増える。PEx の `MAX_PEX_MATCHES` と同値。
 * 超過は一部を切り捨てずに 8030（`too_many_matches`）で拒否する（fail-closed）。
 * 「どの VC が合致するか」だけを使う経路（`findMatchingCredentialIndexes`）は一致を確保しないため対象外。
 */
export const MAX_DCQL_MATCHES = 100_000;

/** 一致件数が `MAX_DCQL_MATCHES` に達していれば 8030（`too_many_matches`）。次の 1 件を確保する前に呼ぶ。 */
export function rejectTooManyDcqlMatches(currentCount: number): void {
  if (currentCount >= MAX_DCQL_MATCHES) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'too_many_matches' },
    });
  }
}
