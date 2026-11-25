/**
 * 共有 HTTPS 取得プリミティブ `fetchSchemaJson` の単体テスト。
 *
 * `validateCredentialSchema` / `resolveTypeMetadata` 経由では届かない分岐、
 * とくに `response.body` を持たない応答（`text()` フォールバック）を直接検証する。
 * エラーコードは呼び出し側が渡すため、ここでは 3015 を使う。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, type VericertsError } from '../../../errors.js';
import { fetchSchemaJson, isHttpsUrl, MAX_SCHEMA_DOCUMENT_BYTES } from '../index.js';

const URL_UNDER_TEST = 'https://issuer.example.com/schemas/person.json';

/** `body` を持たない最小の Response 風オブジェクトを返す `fetchImpl`。 */
function bodylessFetch(text: string, contentType = 'application/json'): typeof fetch {
  return (async () =>
    ({
      url: URL_UNDER_TEST,
      ok: true,
      status: 200,
      headers: new Headers({ 'Content-Type': contentType }),
      body: null,
      text: async () => text,
    }) as unknown as Response) as unknown as typeof fetch;
}

describe('isHttpsUrl', () => {
  it.each([
    ['https://example.com/a.json', true],
    ['http://example.com/a.json', false],
    ['file:///etc/passwd', false],
    ['data:application/json,{}', false],
    ['not a url', false],
  ])('%s → %s', (value, expected) => {
    expect(isHttpsUrl(value)).toBe(expected);
  });
});

describe('fetchSchemaJson — body を持たない応答（text() フォールバック）', () => {
  it('上限以内なら JSON object を返す', async () => {
    const document = await fetchSchemaJson(URL_UNDER_TEST, ErrorCodes.SCHEMA_FETCH_FAILED, {
      fetchImpl: bodylessFetch('{"type":"object"}'),
    });
    expect(document).toEqual({ type: 'object' });
  });

  it('UTF-8 バイト長が上限を超えるなら oversized_body で拒否する', async () => {
    // マルチバイト文字で「文字数は上限未満だがバイト数は上限超過」を作り、
    // バイト長で判定していることを確かめる（あ = UTF-8 3 バイト）。
    const oversized = `"${'あ'.repeat(MAX_SCHEMA_DOCUMENT_BYTES / 2)}"`;
    expect(oversized.length).toBeLessThan(MAX_SCHEMA_DOCUMENT_BYTES);

    let caught: VericertsError | undefined;
    try {
      await fetchSchemaJson(URL_UNDER_TEST, ErrorCodes.SCHEMA_FETCH_FAILED, {
        fetchImpl: bodylessFetch(oversized),
      });
    } catch (err) {
      caught = err as VericertsError;
    }
    expect(caught?.code).toBe(ErrorCodes.SCHEMA_FETCH_FAILED);
    expect(caught?.context).toEqual({ reason: 'oversized_body' });
  });
});

/**
 * `fetchSchemaJson` の `fetchImpl` DI 規律（`internal/fetch-di.ts`）。
 *
 * `fetchJsonWithinLimits` には**関数値しか渡らない**ので、あちらが束ね直せるレシーバは合成した
 * `{ fetchImpl }` であって呼び出し側の DI オブジェクトではない。したがって `this` 参照つきの
 * prototype メソッド実装を壊さないためには、`deps` を持っているこちら側が束ねるしかない。
 */
class PinnedSchemaDeps {
  readonly document: string;
  calls = 0;

  constructor(document: string) {
    this.document = document;
  }

  async fetchImpl(): Promise<Response> {
    this.calls += 1;
    return new Response(this.document, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

describe('fetchSchemaJson の fetchImpl 呼び出し規律', () => {
  it('this 参照つきクラス DI（prototype メソッド）でも取得できる', async () => {
    const deps = new PinnedSchemaDeps('{"type":"object"}');
    const document = await fetchSchemaJson(
      URL_UNDER_TEST,
      ErrorCodes.SCHEMA_FETCH_FAILED,
      deps as unknown as { fetchImpl?: typeof fetch },
    );
    expect(document).toEqual({ type: 'object' });
    expect(deps.calls).toBe(1);
  });
});
