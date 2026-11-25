/**
 * 不正な形状の `failOpenWindow` に対する防御的検証の回帰テスト。
 *
 * `internal/failsafe-policy/gate.ts` の
 * `resolveFailOpen` が `window` に施す形状検証（`typeof window.allow !== 'function'` 等）。
 *
 * `applySchemaViolations` は綺麗に通った場合(`result.valid`)に
 * `resolveWindow(options).clear(key)` を直接呼んでいた。`resolveFailOpen` 経由の判定パス
 * （`gate`）は形状検証済みだが、この成功パスは検証を経ないため、`null` や `clear` を持たない
 * オブジェクトが `failOpenWindow` に注入されると `TypeError` が投げられ、**スキーマに完全適合した
 * 正当なクレデンシャルの検証まで巻き込んで落ちてしまう**。
 *
 * 検証内容:
 * - 不正な形状の `failOpenWindow` を渡しても、綺麗に通ったクレデンシャルの検証は例外にならず
 *   `valid: true` を返す。
 * - `failOpenWindow` を渡さない/不正な形状の場合、FO-3 / FO-4 のゲートも Fail-closed に倒れる
 *   （時間上限を計測できないため）。
 */

import { describe, expect, it } from 'bun:test';
import { applySchemaViolations, schemaFetchFailedResult } from '../fail-safe.js';

/** `allow` / `clear` を持たない不正な形状。 */
const MALFORMED_WINDOWS: ReadonlyArray<[string, unknown]> = [
  ['null', null],
  ['allow / clear を持たないオブジェクト', {}],
  ['allow はあるが clear が関数でない', { allow: () => true, clear: 'not-a-function' }],
];

describe('applySchemaViolations — 不正な形状の failOpenWindow による成功パスのクラッシュ防止', () => {
  it.each(
    MALFORMED_WINDOWS,
  )('不正な failOpenWindow(%s)を渡しても、綺麗に通った検証は例外にならず valid: true を返す', async (_label, failOpenWindow) => {
    const result = await applySchemaViolations(
      'urn:test:window-guard',
      0,
      { valid: true },
      { failOpenWindow: failOpenWindow as never },
    );

    expect(result).toEqual({ valid: true, schemaAvailable: true, warnings: [] });
  });

  it('failOpenWindow を渡さない場合も綺麗に通った検証は例外にならない', async () => {
    const result = await applySchemaViolations('urn:test:window-guard', 0, { valid: true }, {});

    expect(result).toEqual({ valid: true, schemaAvailable: true, warnings: [] });
  });
});

describe('gate — 不正 / 未指定の failOpenWindow は Fail-closed に倒す', () => {
  it.each(
    MALFORMED_WINDOWS,
  )('FO-3 は不正な failOpenWindow(%s)があっても Fail-closed(undefined)を返す', async (_label, failOpenWindow) => {
    const gated = await schemaFetchFailedResult('urn:test:window-guard', 0, {
      requestConsent: () => true,
      onPolicyEvent: () => {},
      failOpenWindow: failOpenWindow as never,
    });

    expect(gated).toBeUndefined();
  });

  it('FO-4 は不正な failOpenWindow があっても違反を通過させない(valid: false)', async () => {
    const result = await applySchemaViolations(
      'urn:test:window-guard',
      0,
      { valid: false, errors: [{ path: '/nickname', message: 'x', required: false }] },
      {
        requestConsent: () => true,
        onPolicyEvent: () => {},
        failOpenWindow: {} as never,
      },
    );

    expect(result.valid).toBe(false);
    expect(result.warnings).toEqual([]);
  });
});
