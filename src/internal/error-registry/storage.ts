/**
 * 6xxx Storage のエラー定義（schemas/error-codes.json）。
 *
 * `message` には秘密情報を一切含めない。破損レコードの内容は
 * 入力由来のため message にも載せない（`gdpr/codec.ts` の正規化方針）。
 */

import type { ErrorRegistryPart } from './definition.js';

/** 6xxx（storage）のコード → 定義。 */
export const STORAGE_ERRORS: ErrorRegistryPart = {
  // storage 上の非 VC レコードが破損している（JSON パース失敗 / 必須フィールド欠落）。
  // 再読み出しでは解消しないため再試行不可。
  '6005': { category: 'storage', retriable: false, message: 'storage レコードが破損しています' },
};
