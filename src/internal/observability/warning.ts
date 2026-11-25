/**
 * 握りつぶした失敗の警告通知（`onWarning`）。
 *
 * SDK の内部層には構造化ロガー（`logger.ts`）の差し込み口が無く、**気づきたい失敗**（監査ログや
 * 末尾アンカーの書込失敗のように、結論は変えないが記録が欠けるもの）を握りつぶしたまま呼び出し側に
 * 伝えられなかった。公開 API は `Logger` ではなく、警告 1 件を受け取る関数 `onWarning` にする
 * （`WalletOptions.onWarning`、および一部の単体 API の最後の任意引数）。
 *
 * 守る規則:
 * - **未指定なら何も起きない**（従来と同じ。`onWarning` が `undefined` のときは呼び出しも生成もしない）。
 * - **気づきたい失敗だけ**が呼ぶ。わざと握りつぶす後始末（ストリームの解放・未処理 rejection を避けるための
 *   `.catch`・リスナの例外など）は呼ばない。呼ばない箇所は、捨てる理由をそのコメントに書く。
 * - 渡すエラーの中身（名前・メッセージ・`VericertsError` のコード）は、既存の PII マスキング
 *   （`maskLogAttributes`）を通してから渡す。例外オブジェクトそのものは渡さない
 *   （スタック・原因（`cause`）・独自プロパティから秘密が漏れるのを避ける）。
 * - **通知の失敗は本処理の結論を変えない**。`onWarning` が投げても、Promise を返して拒否されても握りつぶす
 *   （`safe-emit.ts` と同じ方針。再帰的な障害を避けるためさらに記録はしない）。
 */

import { VericertsError } from '../errors.js';
import { type LogAttributes, maskLogAttributes } from './attribute-mask.js';

/** 警告 1 件。`attributes` はマスキング済み。 */
export interface SdkWarning {
  /** 警告の種類（安定した識別子。例: `dashboard_log.tail_anchor_write_failed`）。集計・分岐に使える。 */
  readonly code: string;
  /** 人が読む説明（固定文言。失敗の中身は含まない）。 */
  readonly message: string;
  /** 警告を出した SDK の部位（`schemas/log-entry.json` の `component` 列挙と同じ表記。例: `sdk.gdpr`）。 */
  readonly component: string;
  /**
   * 失敗の中身（マスキング済み）: `error_name`、`error_message`、`VericertsError` のときは `error_code`。
   * 失敗の原因が例外でないときは空。
   */
  readonly attributes: LogAttributes;
}

/** 警告の受け口。省略可能な引数として公開する。戻り値は使わない。 */
export type OnWarning = (warning: SdkWarning) => void;

/**
 * 例外から、警告に載せる属性（名前・メッセージ・`VericertsError` のコード）を組み立てる。
 * 例外オブジェクトのほかのプロパティ（`cause`・スタック等）は載せない。
 */
function errorAttributes(error: unknown): LogAttributes {
  if (error instanceof Error) {
    const attributes: LogAttributes = { error_name: error.name, error_message: error.message };
    if (error instanceof VericertsError) {
      attributes.error_code = error.code;
    }
    return attributes;
  }
  return { error_message: String(error) };
}

/**
 * 警告を 1 件通知する。`onWarning` が未指定なら何もしない。
 *
 * @param onWarning 受け口（省略可）。
 * @param warning 警告の種類・説明・出所。
 * @param error 失敗の中身。マスキングを通して `attributes` に載せる。
 */
export function emitWarning(
  onWarning: OnWarning | undefined,
  warning: Pick<SdkWarning, 'code' | 'message' | 'component'>,
  error: unknown,
): void {
  if (onWarning === undefined) {
    return;
  }
  try {
    const result: unknown = onWarning({
      ...warning,
      attributes: maskLogAttributes(errorAttributes(error)),
    });
    // 別 realm の Promise と thenable も同じ経路で観測する。
    // 意図的に捨てる: 受け口の失敗で本処理の結論を変えない。ここで記録すると再帰する。
    Promise.resolve(result).catch(() => undefined);
  } catch {
    // 受け口が同期で投げても本処理に伝播させない。
  }
}
