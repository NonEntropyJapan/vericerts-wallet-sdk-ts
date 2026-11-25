/**
 * 公開スキーマ（schemas/log-entry.json）と、実際の Logger 実装
 * （logger.ts）が生成する属性の組み合わせとの整合を検証する回帰テスト。
 *
 * `ts` の付与とシリアライズはアダプタ（pino / winston / console）の責務
 * であり Logger 自体は行わないため、
 * ここでは スキーマ上の最終形（`{ ts, level, msg, ...attrs }`）を組み立てて検証する。
 *
 * バリデータは `credential/json-schema/validate.ts` の自前 JSON Schema（Draft 2020-12
 * サブセット）実装を流用する（スキーマ自体のコンパイルは開発用 CLI が担う。
 * テストファイルはレイヤー検査の対象外 = layer-map.ts の `isTestSupport`）。
 */

import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import type { JsonSchema } from '../credential/json-schema/types.js';
import { validateAgainstSchema } from '../credential/json-schema/validate.js';
import { VericertsError } from '../errors.js';
import { createLogger, errorLogAttributes, type LogAttributes, type Logger } from './logger.js';

const LOG_ENTRY_SCHEMA = JSON.parse(
  readFileSync(new URL('../../../schemas/log-entry.json', import.meta.url), 'utf8'),
) as JsonSchema;

/** `attrs` を捕獲するだけの sink。Logger 自体が実際にアダプタへ渡す最終属性を見るため。 */
function createCapturingSink(capture: { attrs?: LogAttributes }): Logger {
  const sink: Logger = {
    debug: (_msg, attrs) => {
      capture.attrs = attrs;
    },
    info: (_msg, attrs) => {
      capture.attrs = attrs;
    },
    warn: (_msg, attrs) => {
      capture.attrs = attrs;
    },
    error: (_msg, attrs) => {
      capture.attrs = attrs;
    },
    child: () => sink,
  };
  return sink;
}

/** Logger が持たない `ts` フィールドを足し、スキーマに沿ったログエントリの最終形にする。 */
function toLogEntry(level: string, msg: string, attrs: LogAttributes | undefined) {
  return { ts: new Date().toISOString(), level, msg, ...attrs };
}

describe('schemas/log-entry.json ↔ Loggerの整合', () => {
  test('component / operation を束縛した info ログが適合する（wallet.ts / ops.ts の実使用パターン）', () => {
    const capture: { attrs?: LogAttributes } = {};
    const logger = createLogger(createCapturingSink(capture));

    // wallet/did/facade.ts 等の実使用と同じ束縛パターン（component: 'sdk.did'）。
    logger.child({ component: 'sdk.did', operation: 'did.resolve' }).info('DID を解決した', {
      duration_ms: 12,
    });

    const entry = toLogEntry('info', 'DID を解決した', capture.attrs);
    const result = validateAgainstSchema(LOG_ENTRY_SCHEMA, entry);

    expect(result.valid).toBe(true);
  });

  test('errorLogAttributes が付与する error_code を含む error ログが適合する', () => {
    const capture: { attrs?: LogAttributes } = {};
    const logger = createLogger(createCapturingSink(capture));
    const error = new VericertsError('1001');

    logger.child({ component: 'sdk.did' }).error('鍵の解決に失敗した', errorLogAttributes(error));

    const entry = toLogEntry('error', '鍵の解決に失敗した', capture.attrs);
    const result = validateAgainstSchema(LOG_ENTRY_SCHEMA, entry);

    expect(result.valid).toBe(true);
    expect(capture.attrs?.error_code).toBe('1001');
  });

  test('VericertsError 以外は error_code を持たないため属性が空でも適合する', () => {
    const attrs = errorLogAttributes(new Error('boom'));
    const entry = toLogEntry('error', '不明なエラー', attrs);

    expect(attrs).toEqual({});
    expect(validateAgainstSchema(LOG_ENTRY_SCHEMA, entry).valid).toBe(true);
  });

  test.each([
    ['trace_id', 32],
    ['span_id', 16],
  ] as const)('%s は小文字の16進数 %i 桁だけを受理する', (field, length) => {
    const entry = toLogEntry('info', 'request', undefined);
    const valid = '0123456789abcdef'.repeat(length / 16);
    expect(validateAgainstSchema(LOG_ENTRY_SCHEMA, { ...entry, [field]: valid }).valid).toBe(true);
    for (const invalid of [valid.slice(1), `${valid}0`, valid.toUpperCase(), 42]) {
      expect(validateAgainstSchema(LOG_ENTRY_SCHEMA, { ...entry, [field]: invalid }).valid).toBe(
        false,
      );
    }
  });

  test('ts は日時を受理し、時刻を欠く日付を拒否する', () => {
    const entry = toLogEntry('info', 'request', undefined);
    expect(
      validateAgainstSchema(LOG_ENTRY_SCHEMA, { ...entry, ts: '2026-01-02T03:04:05Z' }).valid,
    ).toBe(true);
    expect(validateAgainstSchema(LOG_ENTRY_SCHEMA, { ...entry, ts: '2026-01-02' }).valid).toBe(
      false,
    );
  });

  test.each(['ts', 'level', 'msg'] as const)('必須項目 %s が欠けると不適合になる', (field) => {
    const { [field]: _missing, ...entry } = toLogEntry('info', 'ok', undefined);
    expect(validateAgainstSchema(LOG_ENTRY_SCHEMA, entry).valid).toBe(false);
  });

  test.each(['debug', 'info', 'warn', 'error'])('Logger の %s レベルを受理する', (level) => {
    expect(validateAgainstSchema(LOG_ENTRY_SCHEMA, toLogEntry(level, 'ok', undefined)).valid).toBe(
      true,
    );
  });

  test('level に スキーマの 4 値以外を渡すと不適合になる（enum の回帰検知）', () => {
    const entry = toLogEntry('trace', 'unsupported level', undefined);

    expect(validateAgainstSchema(LOG_ENTRY_SCHEMA, entry).valid).toBe(false);
  });
});
