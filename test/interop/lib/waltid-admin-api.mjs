// test/interop/lib/waltid-admin-api.mjs
//
// walt.id issuer-api / verifier-api の管理系 API 呼び出しで共有する定義。
// `run-waltid-protocol.mjs` を Linterly の 1 ファイル 300 行上限に収めるため切り出した。

export const CREDENTIAL_TYPE = 'OpenBadgeCredential';

/**
 * JSON API 呼び出しの共通ラッパ。`fetchImpl` は既定でグローバル `fetch`
 * （回帰テストは `__tests__/run-waltid-protocol.test.mjs` からスタブを注入する）。
 */
export async function fetchJson(url, options, fetchImpl = fetch) {
  const res = await fetchImpl(url, options);
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { ok: res.ok, status: res.status, body };
}

/**
 * 管理系 API のベース URL を環境変数から取り出す。**既定値は持たない**。
 *
 * ホスト側のポートは run ごとの割り当てで、固定の `localhost:8093` / `:8094` は
 * どの run でも到達できない。到達しない URL を黙って叩くより、未設定は明示的に例外にする。
 * ドライバから見える URL を `docker compose run -e` で渡す。
 * import 時ではなく**呼び出し時**に読む（env を渡さずに import するだけのテストを壊さないため）。
 */
function requireBaseUrl(envName, example) {
  const value = process.env[envName]?.trim();
  if (!value) {
    throw new Error(
      `${envName} が未設定（または空）です。walt.id の管理 API の URL を明示してください` +
        `（ドライバコンテナ内なら ${envName}=${example}。` +
        '実行方法は同梱の Interop README を参照し、`docker compose run -e` で渡す）。' +
        'ホストの公開ポートは run ごとの割り当てのため、既定値は持たない',
    );
  }
  return value;
}

/** walt.id issuer-api の管理系ベース URL（`WALTID_ISSUER_ADMIN_BASE_URL`。未設定は throw）。 */
export function issuerAdminBaseUrl() {
  return requireBaseUrl('WALTID_ISSUER_ADMIN_BASE_URL', 'http://waltid-issuer:7002');
}

/** walt.id verifier-api の管理系ベース URL（`WALTID_VERIFIER_ADMIN_BASE_URL`。未設定は throw）。 */
export function verifierAdminBaseUrl() {
  return requireBaseUrl('WALTID_VERIFIER_ADMIN_BASE_URL', 'http://waltid-verifier:7003');
}
