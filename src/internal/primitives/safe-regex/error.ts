/**
 * 線形時間正規表現エンジン（`safe-regex`）の失敗種別。
 *
 * 本ファイルは非公開の内部実装。メッセージにはパターン本体・マッチ対象の値を含めない。
 */

/** 失敗の種別。 */
export type SafeRegexFailure =
  /** 正規表現として構文不正（`new RegExp(src, 'u')` が拒否する形）。 */
  | 'syntax'
  /** 線形時間では評価できない構文（後方参照・先読み・後読み・修飾子付き群）。 */
  | 'unsupported'
  /** パターン長・展開サイズ・評価ステップが上限を超えた。 */
  | 'too-complex';

/** コンパイル・評価の失敗。呼び出し側は例外を握りつぶさず fail-closed に倒すこと。 */
export class SafeRegexError extends Error {
  /** 失敗の種別。 */
  readonly reason: SafeRegexFailure;

  constructor(reason: SafeRegexFailure) {
    super(`safe-regex: ${reason}`);
    this.name = 'SafeRegexError';
    this.reason = reason;
  }
}
