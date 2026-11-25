/**
 * 6xxx Storage のエラーコード定数（schemas/error-codes.json）。
 *
 * `errors.ts` の `ErrorCodes` に結合される部分定数。値は数値文字列。
 */

/** 6xxx（storage）のコード（数値文字列）。 */
export const STORAGE_ERROR_CODES = {
  /** 非 VC レコードの storage 破損（JSON パース失敗 / 必須フィールド欠落、6005）。 */
  STORAGE_RECORD_CORRUPTED: '6005',
} as const;
