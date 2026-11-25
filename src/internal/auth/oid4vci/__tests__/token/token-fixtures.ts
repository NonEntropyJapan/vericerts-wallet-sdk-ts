/**
 * OID4VCI Token Request のテスト共有フィクスチャ。
 *
 * `requestTokenPreAuthorized` / `requestTokenAuthorizationCode` のテストは
 * `internal/auth/__tests__/oid4vci/oid4vci-token.test.ts` と本ディレクトリの
 * `oid4vci-token.pollution.test.ts` / `oid4vci-token.client-auth.test.ts` /
 * `oid4vci-token.dpop.test.ts` の 4 ファイルに分散しており（いずれも `.linterly.yml` の
 * 1 ファイル 300 行上限を避けるための分割）、どれも「成功レスポンスを返す fetch スタブ」を
 * ほぼ同一のまま個別定義していた。片方だけスタブの挙動が変わるとファイル間で
 * 検証条件がずれるため、PAR 側の `par-fixtures.ts` と同じ方針で 1 か所に集約する。
 *
 * Token Request 系のテストは `fetchImpl` DI シーム追加より前に書かれており、
 * PAR 側（`par-fixtures.ts` の `stubFetchOk` が `FetchLike` を返す設計）とは異なり、
 * 未注入時の既定経路を検証するためグローバル `fetch` を直接差し替える。この既存挙動を
 * そのまま踏襲する（復元は各テストファイルの `afterEach` が行う）。
 */

/** AS が返す正常な Token 応答。 */
export const VALID_TOKEN_BODY = {
  access_token: 'eyJhbGci.access.token',
  token_type: 'Bearer',
  expires_in: 3600,
  c_nonce: 'tZignsnFbp',
  c_nonce_expires_in: 86400,
} as const;

/** fetch スタブが記録する 1 回分の呼び出し（呼び出し側は必要なフィールドだけ参照する）。 */
export interface FetchCall {
  readonly url: string;
  readonly init: { method: string; headers: Record<string, string>; body: string };
  readonly body: URLSearchParams;
}

/**
 * 成功レスポンスを返すグローバル fetch スタブを差し込む。呼び出し内容を `calls` に記録する。
 * `body` 省略時は `VALID_TOKEN_BODY` を返す。
 */
export function stubFetchOk(calls: FetchCall[], body: unknown = VALID_TOKEN_BODY): void {
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    calls.push({
      url,
      init: init as { method: string; headers: Record<string, string>; body: string },
      body: new URLSearchParams(init.body as string),
    });
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as unknown as typeof fetch;
}
