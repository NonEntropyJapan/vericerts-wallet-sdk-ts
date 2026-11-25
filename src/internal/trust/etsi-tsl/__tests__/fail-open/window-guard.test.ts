/**
 * 不正な形状の `failOpenWindow` に対する防御的検証の回帰テスト
 * （`schema-validation/fail-safe.ts` に入れた是正、および
 * `federation/__tests__/fail-open/window-guard.test.ts` と同じバグクラスの再発防止）。
 *
 * `internal/failsafe-policy/gate.ts` の
 * `resolveFailOpen` が `window` に施す形状検証（`typeof window.allow !== 'function'` 等）。
 *
 * `etsi-tsl/fail-open.ts` の `clearTrustedListFailOpenWindow` は `deps.failOpenWindow` の形状を
 * 検証せずに `.clear()` を呼ぶと、`failOpenWindow: null` / `{}` / `{ allow: fn }`（`clear` 無し）の
 * ような不正な形状の注入で生の `TypeError` を投げ、**TSL の取得に成功した正常系までクラッシュ
 * させる**（`validFailOpenWindow` による形状検証で防ぐ）。
 *
 * 検証内容:
 * - 不正な形状の `failOpenWindow` を渡しても、オンラインで正常に取得できる `loadTrustedList` の
 *   呼び出しは例外にならない（成功パスのクラッシュ防止）。
 * - `failOpenWindow` を渡さない場合も同様に例外にならない（既存の既定動作の確認）。
 */

import { describe, expect, it } from 'bun:test';
import { loadTrustedList } from '../../etsi-tsl.js';
import { failOpenHarness } from './harness.js';

/** `allow` / `clear` を持たない不正な形状。 */
const MALFORMED_WINDOWS: ReadonlyArray<[string, unknown]> = [
  ['null', null],
  ['allow / clear を持たないオブジェクト', {}],
  ['allow はあるが clear が関数でない', { allow: () => true, clear: 'not-a-function' }],
];

describe('loadTrustedList — 不正な形状の failOpenWindow による成功パスのクラッシュ防止', () => {
  it.each(
    MALFORMED_WINDOWS,
  )('不正な failOpenWindow(%s)を渡しても、オンラインでの取得成功は例外にならない', async (_label, failOpenWindow) => {
    const h = failOpenHarness();

    const result = await loadTrustedList('https://tsl.example/DE.xml', {
      ...h.base,
      nowSeconds: h.now(),
      failOpenWindow: failOpenWindow as never,
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    });

    expect(result.serviceCertificates.length).toBe(1);
    expect(result.warnings).toBeUndefined();
  });

  it('failOpenWindow を渡さない場合も取得成功は例外にならない', async () => {
    const h = failOpenHarness();

    const result = await loadTrustedList('https://tsl.example/DE.xml', {
      ...h.base,
      nowSeconds: h.now(),
    });

    expect(result.serviceCertificates.length).toBe(1);
    expect(result.warnings).toBeUndefined();
  });
});
