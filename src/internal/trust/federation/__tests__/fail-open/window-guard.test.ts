/**
 * 不正な形状の `failOpenWindow` に対する防御的検証の回帰テスト
 * （`schema-validation/fail-safe.ts` に入れた是正と同じバグクラスの再発防止）。
 *
 * `internal/failsafe-policy/gate.ts` の
 * `resolveFailOpen` が `window` に施す形状検証（`typeof window.allow !== 'function'` 等）。
 *
 * `createEntityConfigurationFailOpen` は以前 `nonObjectPrototypeProperty` の結果が `undefined`
 * かどうかしかチェックしておらず、`failOpenWindow: null` / `{}` / `{ allow: fn }`（`clear` 無し）の
 * ような不正な形状が注入されると、`trackFetch` が成功パスで無検証に `window.clear(key)` を呼び、
 * 生の `TypeError` を投げて **Entity Configuration の取得に成功した正常系までクラッシュさせる**。
 *
 * 検証内容:
 * - 不正な形状の `failOpenWindow` を渡しても、オンラインで正常に取得できる Entity Configuration の
 *   解決は例外にならない（成功パスのクラッシュ防止）。
 * - `failOpenWindow` を渡さない場合も同様に例外にならない（既存の既定動作の確認）。
 */

import { describe, expect, it } from 'bun:test';
import { resolveEntityConfiguration } from '../../entity-configuration.js';
import { LEAF_KEY, NOW_SECONDS, signStatement, toJwk } from '../federation-fixtures.js';
import { failOpenHarness } from './harness.js';

const ENTITY_ID = 'https://leaf.example.eu';
const WELL_KNOWN = `${ENTITY_ID}/.well-known/openid-federation`;

/** `exp` を十分先に置いた自己署名 Entity Configuration。 */
function selfSigned(): string {
  return signStatement(
    LEAF_KEY,
    {
      iss: ENTITY_ID,
      sub: ENTITY_ID,
      iat: NOW_SECONDS - 3600,
      exp: NOW_SECONDS + 4000,
      jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
    },
    { kid: 'leaf-1' },
  );
}

/** `allow` / `clear` を持たない不正な形状。 */
const MALFORMED_WINDOWS: ReadonlyArray<[string, unknown]> = [
  ['null', null],
  ['allow / clear を持たないオブジェクト', {}],
  ['allow はあるが clear が関数でない', { allow: () => true, clear: 'not-a-function' }],
];

describe('createEntityConfigurationFailOpen — 不正な形状の failOpenWindow による成功パスのクラッシュ防止', () => {
  it.each(
    MALFORMED_WINDOWS,
  )('不正な failOpenWindow(%s)を渡しても、オンラインでの取得成功は例外にならない', async (_label, failOpenWindow) => {
    const h = failOpenHarness(new Map([[WELL_KNOWN, selfSigned()]]));

    const config = await resolveEntityConfiguration(ENTITY_ID, {
      ...h.base,
      failOpenWindow: failOpenWindow as never,
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    });

    expect(config.statement.sub).toBe(ENTITY_ID);
    expect(config.warnings).toBeUndefined();
  });

  it('failOpenWindow を渡さない場合も取得成功は例外にならない', async () => {
    const h = failOpenHarness(new Map([[WELL_KNOWN, selfSigned()]]));

    const config = await resolveEntityConfiguration(ENTITY_ID, { ...h.base });

    expect(config.statement.sub).toBe(ENTITY_ID);
    expect(config.warnings).toBeUndefined();
  });
});
