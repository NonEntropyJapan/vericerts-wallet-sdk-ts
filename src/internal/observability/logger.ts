/**
 * 構造化ログの内部配線。
 *
 * 公開 API（`WalletOptions.logger`）が受け取る `Logger` の型定義と、それを SDK 内部から
 * 常に呼べる形に均す `createLogger` を提供する。未注入時は no-op。
 *
 * PII マスキングは**設定変更不可の強制ポリシー**であり、注入されたロガーへ渡る前に
 * 本モジュールが必ず適用する。呼び出し側がうっかり秘密を載せても出力先には届かない。
 * 型は本モジュール（横断）に置き、`wallet/options.ts` が公開 API として再エクスポートする
 * （内部モジュールから公開 API 層への依存を避けるため）。
 *
 * 本モジュールが担うのはキー名による判定まで。値そのものの構造検出（JWT / SD-JWT /
 * COSE）は `pii-mask.ts` に分けてある。`DEBUG=vericerts:*` 名前空間フィルタの
 * パターン照合は `debug-namespace.ts` に分けてある。
 */

import { VericertsError } from '../errors.js';
import { type LogAttributes, type LogValue, maskLogAttributes } from './attribute-mask.js';
import { isDebugNamespaceEnabled } from './debug-namespace.js';

export { type LogAttributes, type LogValue, maskLogAttributes };

/** 構造化ログ出力先。`pino` / `winston` / `console` をアダプタで差し替える。 */
export interface Logger {
  debug(message: string, attrs?: LogAttributes): void;
  info(message: string, attrs?: LogAttributes): void;
  warn(message: string, attrs?: LogAttributes): void;
  error(message: string, attrs?: LogAttributes): void;
  /** 以降の全出力に付く既定属性を足した子ロガーを返す。 */
  child(bindings: LogAttributes): Logger;
}

/** ログレベル。 */
type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/** `DEBUG` 名前空間の既定値（`component` 未束縛時）。 */
const DEFAULT_DEBUG_NAMESPACE = 'vericerts';

/**
 * 束縛済みの `component`（`sdk.did` など）を `DEBUG` 名前空間
 * （`vericerts:did` 等）に変換する。`sdk.` 接頭辞は名前空間側の固定接頭辞 `vericerts:`
 * と重複するため落とし、残りの `.` 区切りは `:` 区切りへ揃える。
 */
function toDebugNamespace(component: LogValue | undefined): string {
  if (typeof component !== 'string' || component.length === 0) {
    return DEFAULT_DEBUG_NAMESPACE;
  }
  const suffix = component.replace(/^sdk\./, '').replace(/\./g, ':');
  return `${DEFAULT_DEBUG_NAMESPACE}:${suffix}`;
}

/**
 * 例外から `error_code` を取り出す。
 *
 * `VericertsError` 以外は SDK が定義したコードを持たないため、推測せず属性ごと落とす
 * （`error_code: "unknown"` のような偽の値を集計へ混ぜない）。
 */
export function errorLogAttributes(error: unknown): LogAttributes {
  return error instanceof VericertsError ? { error_code: error.code } : {};
}

/** 未注入時の出力先。マスキング経路は注入時と共有する。 */
const NOOP_SINK: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
  child: () => NOOP_SINK,
};

/**
 * 注入されたロガーへ「子ロガーの束縛属性のマージ」と「PII マスキング」を挟むラッパ。
 *
 * マスクは束縛時ではなく**出力直前のマージ済み属性に 1 回だけ**掛ける。束縛時に掛けると
 * 呼び出し側属性との合成結果に対して二重に適用され、`child` を経たかどうかで結果が変わる。
 */
class MaskingLogger implements Logger {
  constructor(
    private readonly sink: Logger,
    private readonly bindings: LogAttributes,
  ) {}

  /**
   * `DEBUG=vericerts:*` 環境変数で名前空間が有効化されている場合のみ出力する
   * （本番既定は Off）。名前空間は束縛済みの `component` から導く。
   */
  debug(message: string, attrs?: LogAttributes): void {
    if (!isDebugNamespaceEnabled(toDebugNamespace(this.bindings.component))) {
      return;
    }
    this.emit('debug', message, attrs);
  }

  info(message: string, attrs?: LogAttributes): void {
    this.emit('info', message, attrs);
  }

  warn(message: string, attrs?: LogAttributes): void {
    this.emit('warn', message, attrs);
  }

  error(message: string, attrs?: LogAttributes): void {
    this.emit('error', message, attrs);
  }

  child(bindings: LogAttributes): Logger {
    // 後から足した束縛が既存を上書きする（component の付け替えを可能にする）。
    return new MaskingLogger(this.sink, { ...this.bindings, ...bindings });
  }

  private emit(level: LogLevel, message: string, attrs?: LogAttributes): void {
    this.sink[level](message, this.mergeAndMask(attrs));
  }

  /** 束縛属性と呼び出し側属性を合成してマスクする（衝突は呼び出し側が勝つ）。 */
  private mergeAndMask(attrs?: LogAttributes): LogAttributes | undefined {
    const masked = maskLogAttributes({ ...this.bindings, ...attrs });
    // 空オブジェクトは渡さない（`attrs` 未指定の呼び出しと同じ形にする）。
    return Object.keys(masked).length === 0 ? undefined : masked;
  }
}

/**
 * SDK 内部で使う `Logger` を組み立てる。
 *
 * @param sink `WalletOptions.logger`。未注入（`undefined`）なら no-op に落とす。
 * @returns PII マスキングを強制するラッパ。常に呼び出し可能で `undefined` にならない。
 */
export function createLogger(sink: Logger | undefined): Logger {
  return new MaskingLogger(sink ?? NOOP_SINK, {});
}
