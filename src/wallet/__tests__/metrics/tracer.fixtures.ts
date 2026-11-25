/**
 * Wallet ファサードのトレース配線テスト用の記録トレーサ。
 *
 * `createWallet({ tracer })` に渡して、実処理経路が Span を開始したか・属性（`did.method` /
 * `vc.format` / `*.result` 等）とステータス・例外記録・`end()` を実際に積んだかを検証する。
 * `wallet.resolve-methods.test.ts` と `credential/wallet.credential.trace.test.ts` から使う。
 *
 * 本ファイルは `*.test.ts` ではないため bun test の探索対象にならない。
 */

import type { AttributeValue, Span, Tracer } from '../../options.js';

/** 記録した Span 1 本。 */
export interface RecordedSpan {
  readonly name: string;
  /** `setAttribute` で積まれた属性（後勝ち）。 */
  readonly attributes: Record<string, AttributeValue>;
  /** `recordException` に渡された例外。 */
  readonly exceptions: Error[];
  /** 最後の `setStatus`。未呼び出しなら `undefined`。 */
  status?: { readonly status: 'ok' | 'error'; readonly description: string | undefined };
  /** `end()` が呼ばれたか。 */
  ended: boolean;
}

/** 記録トレーサとその記録先。 */
export interface RecordingTracer {
  readonly tracer: Tracer;
  readonly spans: RecordedSpan[];
}

/** 呼び出しを配列に貯めるだけのトレーサを作る。 */
export function recordingTracer(): RecordingTracer {
  const spans: RecordedSpan[] = [];
  const tracer: Tracer = {
    startSpan: (name) => {
      const recorded: RecordedSpan = { name, attributes: {}, exceptions: [], ended: false };
      spans.push(recorded);
      const span: Span = {
        setAttribute: (key, value) => {
          recorded.attributes[key] = value;
        },
        addEvent: () => {},
        recordException: (err) => {
          recorded.exceptions.push(err);
        },
        setStatus: (status, description) => {
          recorded.status = { status, description };
        },
        end: () => {
          recorded.ended = true;
        },
      };
      return span;
    },
  };
  return { tracer, spans };
}

/** 指定名の Span を 1 本探す（無ければ `undefined`）。 */
export function findSpan(spans: readonly RecordedSpan[], name: string): RecordedSpan | undefined {
  return spans.find((span) => span.name === name);
}
