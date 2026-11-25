/**
 * SDK 共通エラークラス `VericertsError` とエラーコードレジストリ。
 *
 * SDK のエラーは、機械可読なコード（数値文字列）、カテゴリ、再試行可否を持つ。
 *
 * セキュリティ上の注意:
 * - `message` は秘密を含まない静的な日本語とする。ニーモニック / seed / privateKey /
 *   導出パス等の機密情報を埋め込まない。`context` に PII を含めない。
 * - 原因 (`cause`) は Error 標準の `options.cause` に委譲する。@scure 由来の例外など、
 *   メッセージにエントロピー等の秘密を含み得るものは `cause` を渡さず握りつぶす。
 */

import { ACCOUNT_PROTOCOL_ERROR_CODES } from './error-codes/account-protocol.js';
import { CREDENTIAL_ERROR_CODES } from './error-codes/credential.js';
import { DIDCOMM_ERROR_CODES } from './error-codes/didcomm.js';
import { KEY_DID_ERROR_CODES } from './error-codes/key-did.js';
import { STORAGE_ERROR_CODES } from './error-codes/storage.js';
import { TRUST_EUDI_ERROR_CODES } from './error-codes/trust-eudi.js';
import { ERROR_REGISTRY } from './error-registry.js';
import { ownProperty } from './prototype-safety/own-property.js';

/**
 * SDK のエラーコード定数（数値文字列）。定義本体は ERROR_REGISTRY と同じ 6 ドメイン
 * （`error-codes/*.ts`）に切り出し、本ファイルはそれらを結合して公開する。
 * キー名・値・readonly 性は分割前と同一で、consumer から見た `ErrorCodes.X` の意味は変わらない。
 */
export const ErrorCodes = {
  ...KEY_DID_ERROR_CODES,
  ...CREDENTIAL_ERROR_CODES,
  ...ACCOUNT_PROTOCOL_ERROR_CODES,
  ...TRUST_EUDI_ERROR_CODES,
  ...STORAGE_ERROR_CODES,
  ...DIDCOMM_ERROR_CODES,
} as const;

/** `ErrorCodes` の値（数値文字列）の union 型。 */
export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

/** `VericertsError` のオプション引数。 */
export interface VericertsErrorOptions {
  /** 追加メタ情報。PII を含めてはならない。 */
  readonly context?: Record<string, unknown>;
  /** 原因となった例外等。Error 標準の `options.cause` に委譲する。 */
  readonly cause?: unknown;
}

/**
 * SDK 共通エラークラス。`code` / `category` / `retriable` を保持し、
 * consumer 側は `instanceof VericertsError` と `code` で分岐できる。
 */
export class VericertsError extends Error {
  /** エラーを識別する数値文字列（例: `1001`）。 */
  readonly code: ErrorCode;
  /** エラーのカテゴリ（例: `key`）。 */
  readonly category: string;
  /** 再試行で解決し得るか。 */
  readonly retriable: boolean;
  /** 追加メタ情報（PII 不可）。省略時は `undefined`。 */
  readonly context?: Record<string, unknown>;

  /**
   * @param code SDK のエラーコード。
   * @param options 追加メタ（`context`）と原因（`cause`）。
   */
  constructor(code: ErrorCode, options?: VericertsErrorOptions) {
    const def = ERROR_REGISTRY[code];
    // `options` は呼び出し側が渡すプレーンオブジェクトであり、`cause` / `context` のどちらか
    // 片方だけを省略する呼び出しが SDK 全域に存在する。オプショナルチェイニングは `options` が
    // `undefined` の場合しか短絡しないため、実オブジェクトに対する省略側の読み取りは
    // `Object.prototype` まで鎖を辿ってしまう。own 限定で読み、汚染値を拾わないようにする。
    const cause = options === undefined ? undefined : ownProperty<unknown>(options, 'cause');
    const context =
      options === undefined ? undefined : ownProperty<Record<string, unknown>>(options, 'context');
    super(def.message, cause !== undefined ? { cause } : undefined);
    this.name = 'VericertsError';
    this.code = code;
    this.category = def.category;
    this.retriable = def.retriable;
    if (context !== undefined) {
      this.context = context;
    }
  }
}
