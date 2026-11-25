/**
 * 高レベル Verifier API の `errors` / `warnings` に含まれる構造化された失敗理由。
 * 呼び出し側は機械可読な `code` で分岐し、利用者への説明には `message` を使える。
 *
 * セキュリティ上の注意:
 * - `message` は `ERROR_REGISTRY` の**静的な**文言をそのまま使う。検証対象の JWT / VC 本文 /
 *   開示値 / 鍵素材に由来する文字列は一切載せない。
 * - `context` は個人情報を含まない `VericertsError.context` を引き継ぐ。ここで新たな情報は追加しない。
 * - 例外の `cause`（@scure 由来のメッセージ等、秘密を含み得る）は**引き継がない**。
 */

import { ERROR_REGISTRY } from '../error-registry.js';
import type { ErrorCode, VericertsError } from '../errors.js';

/** 検証の失敗理由 1 件。 */
export interface VerificationIssue {
  /** SDK のエラーコードを表す数値文字列（例: `3010`）。分岐はこの値で行う。 */
  readonly code: ErrorCode;
  /** コードに対応する静的な説明（`ERROR_REGISTRY` の文言）。秘密を含まない。 */
  readonly message: string;
  /** 追加メタ情報（PII 不可）。`VericertsError.context` が無い場合はキー自体を持たない。 */
  readonly context?: Record<string, unknown>;
}

/**
 * `VericertsError` を `VerificationIssue` へ変換する（`cause` は引き継がない）。
 *
 * @param error 低レベル primitive が投げた SDK 共通エラー。
 * @returns 同じ `code` / `message` を持つ issue（`context` があればそのまま引き継ぐ）。
 */
export function verificationIssueFromVericertsError(error: VericertsError): VerificationIssue {
  return {
    code: error.code,
    message: error.message,
    ...(error.context !== undefined ? { context: error.context } : {}),
  };
}

/**
 * エラーコードだけが分かっている失敗（内包 VC の `credentialResults` 等）を issue へ変換する。
 *
 * @param code SDK のエラーコード。
 * @returns レジストリの静的な文言を添えた issue。
 */
export function verificationIssueFromCode(code: ErrorCode): VerificationIssue {
  return { code, message: ERROR_REGISTRY[code].message };
}
