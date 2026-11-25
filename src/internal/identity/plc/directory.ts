/**
 * PLC ディレクトリへの HTTP。取得は GET、公開は POST。
 *
 * - 宛先ホストは DID から導出しない。`directoryUrl`（既定 `https://plc.directory`）は呼び出し側の設定値で、
 *   `https:` かつ公開ホストだけを受け付ける（それ以外は送信せず `2003`、`context.reason: 'insecure_directory_url'`）。
 * - GET は `internal/http/public-redirect-fetch.ts` でリダイレクトをホップごとに公開 HTTPS 宛へ縛って追従する。
 *   POST は 3xx に追従しない（`redirect: 'manual'`）。ブラウザ系ランタイムは 3xx を追従できず `2003` になる。
 * - 取得本文は `MAX_DOCUMENT_BYTES`（1 MiB）の内側で読み、読んだ文字数を解決スコープへ計上してからパースする
 *   （GET は `network/http-resolver.ts` の `fetchResolverJson` を再利用する）。
 *
 * セキュリティ上の注意: 例外メッセージや `context` に DID・URL・応答本文を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { discardBody } from '../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectedPostResponse } from '../../http/public-https-url.js';
import { fetchResolverJson } from '../network/http-resolver.js';
import type { ResolutionWorkBudget } from '../resolution-budget.js';

/** 既定のディレクトリ。 */
export const DEFAULT_PLC_DIRECTORY_URL = 'https://plc.directory';

/** 取得・公開 1 回のタイムアウト（ミリ秒）。 */
const TIMEOUT_MS = 10_000;

/** DID Document は `application/did+ld+json`、監査ログは `application/json` で返る。 */
const READ_CONTENT_TYPES = ['application/json', 'application/did+ld+json', 'application/did+json'];

function notFound(reason?: string): VericertsError {
  return new VericertsError(
    ErrorCodes.DID_NOT_FOUND,
    reason === undefined ? undefined : { context: { reason } },
  );
}

/**
 * ディレクトリのベース URL を検証し、末尾の `/` を除いて返す。
 *
 * @throws `https:` かつ公開ホストでない・クエリ / フラグメント / 認証情報を持つ場合（code `2003`）。
 */
export function directoryBase(directoryUrl: string): string {
  let url: URL;
  try {
    url = new URL(directoryUrl);
  } catch {
    throw notFound('insecure_directory_url');
  }
  const hasExtras =
    url.search !== '' || url.hash !== '' || url.username !== '' || url.password !== '';
  if (hasExtras || !isPublicHttpsUrl(url.toString())) {
    throw notFound('insecure_directory_url');
  }
  return url.toString().replace(/\/+$/, '');
}

/**
 * ディレクトリから JSON を GET して返す（取得・本文上限・スコープ計上は `network/http-resolver.ts` と共通）。
 *
 * @param url 取得先（`directoryBase` + パス）。
 * @param fetchFn fetch 実装（未指定ならグローバル `fetch`）。
 * @param scope 解決スコープの予算。取得の前に残量を確かめ、本文を読み終えた直後に文字数を計上する。
 * @returns パース済みの JSON。
 * @throws 取得失敗（ネットワーク / タイムアウト / 非 2xx / 上限超過 / リダイレクト違反。code `2003`）、
 *         Content-Type 不正・JSON 不正（code `2010`）、予算超過（code `2001`）。
 */
export async function getDirectoryJson(
  url: string,
  fetchFn: typeof fetch | undefined,
  scope?: ResolutionWorkBudget,
): Promise<unknown> {
  const { value } = await fetchResolverJson({
    url,
    accept: 'application/json',
    contentTypes: READ_CONTENT_TYPES,
    fetchFn,
    scope,
  });
  return value;
}

/**
 * 署名済み操作をディレクトリへ POST する。成功は 2xx。リダイレクトには追従しない。
 *
 * @param url 公開先（`directoryBase` + `/<did>`）。
 * @param body 検証済みの署名済み操作の JSON 本文（再シリアライズせず送る）。
 * @param fetchFn fetch 実装（未指定ならグローバル `fetch`）。
 * @throws ネットワーク失敗・タイムアウト・非 2xx・リダイレクト（code `2003`、`context.reason: 'plc_submit_failed'`
 *         / リダイレクトは `insecure_directory_url`）。
 */
export async function postDirectoryOperation(
  url: string,
  body: string,
  fetchFn: typeof fetch | undefined,
): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response | undefined;
  try {
    try {
      response = await (fetchFn ?? fetch)(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      throw notFound('plc_submit_failed');
    }
    if (isRedirectedPostResponse(url, response)) {
      throw notFound('insecure_directory_url');
    }
    if (!response.ok) {
      throw notFound('plc_submit_failed');
    }
  } finally {
    clearTimeout(timer);
    discardBody(response);
  }
}
