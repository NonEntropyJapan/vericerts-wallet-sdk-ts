/**
 * Wallet ファサードのログ配線テスト用の記録ロガー。
 *
 * `createWallet({ logger })` に渡して、実処理経路が `info` / `error` を実際に呼んだかと、
 * そのとき積まれた属性（`component` / `operation` / `duration_ms` 等）を検証するために使う。
 * `wallet.resolve-methods.test.ts` と `credential/wallet.credential.test.ts` の両方から使う。
 *
 * 本ファイルは `*.test.ts` ではないため bun test の探索対象にならない。
 */

import type { LogAttributes, Logger } from '../../options.js';

/** 記録したログ 1 件。 */
export interface RecordedLog {
  readonly level: 'debug' | 'info' | 'warn' | 'error';
  readonly message: string;
  readonly attrs: LogAttributes | undefined;
}

/** 記録ロガーとその記録先。 */
export interface RecordingLogger {
  readonly logger: Logger;
  readonly logs: RecordedLog[];
}

/**
 * 呼び出しを配列に貯めるだけのロガーを作る。
 *
 * SDK 側のラッパ（`createLogger`）が束縛のマージとマスキングを済ませてから呼ぶため、
 * ここでの `child` は呼ばれない（型を満たすため自分自身を返す）。
 */
export function recordingLogger(): RecordingLogger {
  const logs: RecordedLog[] = [];
  const record =
    (level: RecordedLog['level']) =>
    (message: string, attrs?: LogAttributes): void => {
      logs.push({ level, message, attrs });
    };
  const logger: Logger = {
    debug: record('debug'),
    info: record('info'),
    warn: record('warn'),
    error: record('error'),
    child: () => logger,
  };
  return { logger, logs };
}

/** 指定レベル・指定メッセージのログを 1 件探す（無ければ `undefined`）。 */
export function findLog(
  logs: readonly RecordedLog[],
  level: RecordedLog['level'],
  message: string,
): RecordedLog | undefined {
  return logs.find((entry) => entry.level === level && entry.message === message);
}
