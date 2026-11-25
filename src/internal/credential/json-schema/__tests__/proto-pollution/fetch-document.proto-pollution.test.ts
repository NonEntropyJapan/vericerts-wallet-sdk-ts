/**
 * `fetchSchemaJson` の `fetchImpl` 読み取り規律（`own-property.ts`）。
 *
 * この経路の取得元 URL は VC 由来（`credentialSchema` / `vct`）であり、取得した文書は
 * `validateCredentialSchema` / Type Metadata 解決が**検証判断の土台**として使う。`fetchImpl` を
 * 素のプロトタイプ鎖読み（`deps.fetchImpl`）で取り出すと、`fetchImpl` を**指定していない**
 * 正当な呼び出しが `Object.prototype.fetchImpl` の汚染値を掴み、スキーマ文書そのものを
 * 攻撃者に差し替えられる。
 *
 * 逆に own 限定（`ownProperty`）で読むのも誤りで、`class Deps { async fetchImpl() {…} }` のような
 * 正当なプロトタイプメソッド注入が「未指定」と判定され、証明書ピンニング付きの `fetch` が
 * 無言でグローバル `fetch` に差し替わる。両方向を 1 ファイルで固定する。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import { fetchSchemaJson } from '../../fetch-document.js';

const SCHEMA_URL = 'https://issuer.example.com/schemas/person.json';

/** 指定の JSON を返す `fetch` 互換関数と、呼ばれた回数の記録。 */
function recordingFetch(body: string): { impl: typeof fetch; calls: () => number } {
  let calls = 0;
  const impl = (async () => {
    calls += 1;
    const res = new Response(body, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
    Object.defineProperty(res, 'url', { value: SCHEMA_URL });
    return res;
  }) as unknown as typeof fetch;
  return { impl, calls: () => calls };
}

/** グローバル `fetch` を差し替えて `fn` を実行し、必ず戻す（実ネットワークへ出さないため）。 */
async function withGlobalFetch<T>(impl: typeof fetch, fn: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  try {
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

describe('fetchSchemaJson の fetchImpl 読み取り', () => {
  test('`Object.prototype.fetchImpl` の汚染値は採用しない（グローバル fetch へ倒れる）', async () => {
    const attacker = recordingFetch('{"evil":true}');
    const legitimate = recordingFetch('{"type":"object"}');

    const document = await withGlobalFetch(legitimate.impl, () =>
      withPollutedPrototypeAsync({ fetchImpl: attacker.impl }, () =>
        // `deps` を渡さない = `fetchImpl` を指定していない正当な呼び出し。
        fetchSchemaJson(SCHEMA_URL, ErrorCodes.SCHEMA_FETCH_FAILED),
      ),
    );

    expect(document).toEqual({ type: 'object' });
    expect(attacker.calls()).toBe(0);
    expect(legitimate.calls()).toBe(1);
  });

  test('空リテラルの `deps` を渡した場合も汚染値を採用しない', async () => {
    const attacker = recordingFetch('{"evil":true}');
    const legitimate = recordingFetch('{"type":"object"}');

    const document = await withGlobalFetch(legitimate.impl, () =>
      withPollutedPrototypeAsync({ fetchImpl: attacker.impl }, () =>
        fetchSchemaJson(SCHEMA_URL, ErrorCodes.SCHEMA_FETCH_FAILED, {}),
      ),
    );

    expect(document).toEqual({ type: 'object' });
    expect(attacker.calls()).toBe(0);
  });

  test('プロトタイプメソッドとして注入した `fetchImpl` は採用する（own 限定にしない）', async () => {
    const injected = recordingFetch('{"type":"object"}');
    const globalCalls = recordingFetch('{"from":"global"}');
    class SchemaDeps {
      fetchImpl(...args: Parameters<typeof fetch>): Promise<Response> {
        return injected.impl(...args);
      }
    }

    const document = await withGlobalFetch(globalCalls.impl, () =>
      fetchSchemaJson(SCHEMA_URL, ErrorCodes.SCHEMA_FETCH_FAILED, new SchemaDeps()),
    );

    expect(document).toEqual({ type: 'object' });
    expect(injected.calls()).toBe(1);
    expect(globalCalls.calls()).toBe(0);
  });
});
