/**
 * 分散トレースの内部配線。
 *
 * 公開 API（`WalletOptions.tracer`）が受け取る `Tracer` / `Span` の型定義と、それを SDK 内部から
 * 常に呼べる形に均す `createTracer` を提供する。未注入時は no-op を使う。
 * OTel SDK パッケージには依存しない（Exporter の結線は
 * 呼び出し側が注入する `Tracer` 実装の責務）。
 *
 * ロガー（`logger.ts`）と違い、本モジュールは属性へマスキング層を挟まない。トレース属性は
 * Issuer / Subject の生の DID・URL を含めず、載せる値は SDK 内部の
 * 計装側で選ぶ（呼び出し側から任意の属性が流れ込む経路ではない）。計装を足す際は例外メッセージや
 * 秘密情報をそのまま属性・イベントへ載せないこと。
 *
 * 型は本モジュール（横断）に置き、`wallet/options.ts` が公開 API として再エクスポートする
 * （内部モジュールから公開 API 層への依存を避けるため）。
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { VericertsError } from '../errors.js';
import type { LogValue } from './logger.js';
import { safeEmit } from './safe-emit.js';

/**
 * Span 属性に載せられる値。
 *
 * ログ属性（`LogValue`）と同じ形を使う。属性の型を 2 つに分裂させると、同じ値を
 * ログと Span の双方へ出す計装で片側だけ通らない、という噛み合わせの悪さが生じるため。
 */
export type AttributeValue = LogValue;

/** Span 属性。 */
export type Attributes = Record<string, AttributeValue>;

/** `Tracer.startSpan` のオプション。 */
export interface SpanOptions {
  /** Span 生成時に付ける属性。 */
  readonly attributes?: Attributes;
}

/**
 * 進行中の処理 1 区間。
 *
 * 親子関係は Span 名の規約 `<component>.<operation>` で表し、本インターフェースは
 * 明示的な親 Span を引数に取らない。
 */
export interface Span {
  setAttribute(key: string, value: AttributeValue): void;
  addEvent(name: string, attrs?: Attributes): void;
  recordException(err: Error): void;
  setStatus(status: 'ok' | 'error', description?: string): void;
  end(): void;
}

/** トレース出力先。OTel Tracer 等をアダプタで差し替える。 */
export interface Tracer {
  startSpan(name: string, opts?: SpanOptions): Span;
}

/** 未注入時の Span。状態を持たないので 1 つを使い回す。 */
const NOOP_SPAN: Span = {
  setAttribute: () => {},
  addEvent: () => {},
  recordException: () => {},
  setStatus: () => {},
  end: () => {},
};

/** 未注入時の出力先。`startSpan` は何もしない Span を返す。 */
const NOOP_TRACER: Tracer = {
  startSpan: () => NOOP_SPAN,
};

/**
 * SDK 内部で使う `Tracer` を組み立てる。
 *
 * @param sink `WalletOptions.tracer`。未注入（`undefined`）なら no-op に落とす。
 * @returns 常に呼び出し可能な `Tracer`（`undefined` にならない）。注入時はそのまま用いる。
 */
export function createTracer(sink: Tracer | undefined): Tracer {
  return sink ?? NOOP_TRACER;
}

/** Span 属性の識別子は SHA-256 の先頭 16 桁を使う。ログ属性の識別子は先頭 8 桁。 */
const ATTRIBUTE_HASH_PREFIX_LENGTH = 16;

/**
 * 識別子を `sha256` hex の先頭 16 桁に潰す。
 *
 * Issuer / Subject の生の DID・URL を Span 属性に含めないため、発行者のような識別子を
 * Span 属性に載せるときは必ず本関数を通す。元の値は復元できないが同一性の追跡には使える。
 */
export function hashAttributeValue(value: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(value))).slice(0, ATTRIBUTE_HASH_PREFIX_LENGTH);
}

/**
 * `setStatus('error', …)` の description を作る。
 *
 * `VericertsError` のコードだけを載せる（`errorLogAttributes` と同じ方針）。例外の
 * `message` は外部ライブラリ由来だと秘密や生の DID / URL を含み得るため、トレースには出さない。
 */
function spanErrorDescription(error: unknown): string | undefined {
  return error instanceof VericertsError ? error.code : undefined;
}

/**
 * `startSpan` と、返した Span の全操作を best-effort にする（`safeEmit`）。
 *
 * 注入された Tracer / Span が例外を投げても、本処理の成功結果や元のエラーを置換してはならない
 * （`safe-emit.ts`）。`startSpan` 自体が失敗した場合は no-op Span に落とす。
 */
function bestEffortSpan(tracer: Tracer, name: string): Span {
  let span = NOOP_SPAN;
  safeEmit(() => {
    span = tracer.startSpan(name);
  });
  const inner = span;
  return {
    setAttribute: (key, value) => safeEmit(() => inner.setAttribute(key, value)),
    addEvent: (eventName, attrs) => safeEmit(() => inner.addEvent(eventName, attrs)),
    recordException: (err) => safeEmit(() => inner.recordException(err)),
    setStatus: (status, description) => safeEmit(() => inner.setStatus(status, description)),
    end: () => safeEmit(() => inner.end()),
  };
}

/**
 * 処理 1 区間を Span で包む。
 *
 * 成否（`<component>.result` = `success` / `failure`）・`setStatus`・例外記録・`end` という
 * 計装のうち全 Span 共通の部分をここに集約し、Span 固有の属性は `run` が受け取る `Span` へ
 * 直接載せる（成功して初めて分かる属性があるため）。例外は加工せずそのまま再送出する。Tracer / Span の
 * 例外は握り潰し、本処理の結果・元の例外を置換しない。
 *
 * @param tracer 出力先（未注入時は no-op）。
 * @param name Span 名（`<component>.<operation>`）。
 * @param resultAttribute 成否を載せる属性名（`did.result` / `vc.result` 等）。
 * @param run 計装対象の処理。
 */
export async function traceSpan<T>(
  tracer: Tracer,
  name: string,
  resultAttribute: string,
  run: (span: Span) => Promise<T>,
): Promise<T> {
  const span = bestEffortSpan(tracer, name);
  try {
    const value = await run(span);
    span.setAttribute(resultAttribute, 'success');
    span.setStatus('ok');
    return value;
  } catch (error) {
    span.recordException(error instanceof Error ? error : new Error(String(error)));
    span.setAttribute(resultAttribute, 'failure');
    span.setStatus('error', spanErrorDescription(error));
    throw error;
  } finally {
    // 成否・再送出にかかわらず必ず閉じる（閉じ損ねた Span は Exporter 側で滞留する）。
    span.end();
  }
}
