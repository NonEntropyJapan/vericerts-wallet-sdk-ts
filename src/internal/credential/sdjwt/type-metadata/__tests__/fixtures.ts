/**
 * Type Metadata テストの共有フィクスチャ（モック禁止方針に沿った DI フェッチャ）。
 *
 * 実ネットワークを使わないために `fetchImpl` を注入する（`credential/manifest` のテストと同方針）。
 * `fetch` 自体をグローバルに差し替えず、実装が公開している DI シームのみを使う。
 */

/** 1 URL 分の応答定義。 */
export interface StubResponse {
  /** JSON 本文（`body` を直接指定しない場合に直列化される）。 */
  readonly json?: unknown;
  /** 生の本文（JSON パース失敗のテスト用）。 */
  readonly body?: string;
  /** HTTP ステータス（既定 200）。 */
  readonly status?: number;
  /** Content-Type（既定 `application/json`）。 */
  readonly contentType?: string;
  /** リダイレクト後の最終 URL（既定はリクエスト URL）。 */
  readonly finalUrl?: string;
  /** `true` ならネットワークエラーとして reject する。 */
  readonly networkError?: boolean;
}

/** URL → 応答のスタブと、実際に要求された URL の記録。 */
export interface FetchStub {
  /** 実装へ渡す `fetchImpl`。 */
  readonly fetchImpl: typeof fetch;
  /** 要求された URL の履歴（キャッシュ検証に使う）。 */
  readonly requested: string[];
}

/** URL → 応答定義のマップから `fetchImpl` を組み立てる。 */
export function createFetchStub(routes: Readonly<Record<string, StubResponse>>): FetchStub {
  const requested: string[] = [];
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input.toString();
    requested.push(url);
    const route = routes[url];
    if (route === undefined) {
      throw new TypeError('fetch failed');
    }
    if (route.networkError === true) {
      throw new TypeError('fetch failed');
    }
    const body = route.body ?? JSON.stringify(route.json ?? {});
    const response = new Response(body, {
      status: route.status ?? 200,
      headers: { 'Content-Type': route.contentType ?? 'application/json' },
    });
    // Response.url は読み取り専用のため、リダイレクト後 URL の検証用に上書きする。
    Object.defineProperty(response, 'url', { value: route.finalUrl ?? url });
    return response;
  }) as unknown as typeof fetch;
  return { fetchImpl, requested };
}

export const BASE_VCT = 'https://issuer.example.com/vct/base/1.0';
export const CHILD_VCT = 'https://issuer.example.com/vct/identity/1.0';
export const SCHEMA_URI = 'https://issuer.example.com/schema/identity.json';

/** 親（継承元）Type Metadata。`given_name` を必須にする。 */
export const BASE_METADATA = {
  vct: BASE_VCT,
  name: 'Base Credential',
  description: '基底の VC 種別',
  schema: {
    type: 'object',
    required: ['given_name'],
    properties: {
      given_name: { type: 'string', minLength: 1 },
      nickname: { type: 'string', maxLength: 8 },
    },
  },
  claims: [
    { path: ['given_name'], display: [{ lang: 'ja-JP', label: '名' }] },
    { path: ['nickname'], display: [{ lang: 'ja-JP', label: '愛称' }] },
  ],
};

/** 子 Type Metadata。`name` と `nickname` の表示を上書きし、親のスキーマを継承する。 */
export const CHILD_METADATA = {
  vct: CHILD_VCT,
  name: 'Identity Credential',
  extends: BASE_VCT,
  claims: [{ path: ['nickname'], display: [{ lang: 'ja-JP', label: 'ニックネーム' }] }],
};
