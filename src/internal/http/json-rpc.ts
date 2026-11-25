/**
 * JSON-RPC over fetch の 1 往復（タイムアウト・本文上限・seam 解決・本文解放）— 横断プリミティブ。
 *
 * 「外部の JSON-RPC エンドポイントへ POST して `result` を受け取る」経路は SDK に複数ある
 * （`aa/fetch-adapter.ts` の Bundler、`aa/paymaster-fetch-adapter.ts` の Paymaster、
 * `auth/siwe/siwe-erc1271-adapter.ts` の ERC-1271 `eth_call`）。**エンドポイントが攻撃者の
 * 影響下にあり得るという攻撃面は同一**なので、必要な硬化も同一である。
 *
 * 本文上限、タイムアウト、fetch の receiver 束縛、本文の解放をすべての経路で共有する。
 * メソッドと params、JSON-RPC エラーの変換は各呼び出し側が決める。
 *
 *
 * セキュリティ上の注意:
 * - URL・レスポンス本文・JSON-RPC error message を VericertsError の message / context / cause に
 *   伝播させない。
 * - タイムアウトは**本文読了まで**を 1 つの `AbortController` で覆う（`clearTimeout` は本文読了後）。
 *   ヘッダだけ先に返して本文を引き延ばす相手に無期限に待たされない。
 * - 応答本文は外部由来なので 1 MiB 上限（`body-limit.ts`）を課す。
 * - 読まずに失敗へ倒す経路でも本文を解放する（`discardBody`）。
 * - seam は裸で呼ばずレシーバを束ねて呼ぶ（`fetch-di.ts` の規則 2）。
 */

import { type ErrorCode, ErrorCodes, VericertsError } from '../errors.js';
import { type FetchLike, resolveInjectedFetch } from '../fetch-di.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import { declaresOversizedBody, discardBody, readBodyWithinLimit } from './body-limit.js';
import { isRedirectedPostResponse } from './public-https-url.js';

/**
 * JSON-RPC のタイムアウト（ミリ秒）。他の外部通信（`http/fetch-json.ts` 等）と揃えて 10 秒。
 */
export const JSON_RPC_TIMEOUT_MS = 10_000;

/** トランスポート / レスポンス形状の失敗（本文・URL を伝播させない）。 */
function transportFailure(): VericertsError {
  return new VericertsError(ErrorCodes.CHAIN_SUBMIT_FAILED);
}

/**
 * 上限内で読んだ本文を JSON-RPC のレスポンス body としてパースする。
 *
 * `parseJsonWithoutPrototype` が返すオブジェクトはプロトタイプを持たないため、欠落したフィールドの読み取りは `undefined` になる。
 */
function parseJsonRpcBody(text: string): { result?: unknown; error?: unknown } {
  let payload: unknown;
  try {
    payload = parseJsonWithoutPrototype(text);
  } catch {
    throw transportFailure();
  }
  if (payload === null || typeof payload !== 'object') {
    throw transportFailure();
  }
  return payload as { result?: unknown; error?: unknown };
}

/**
 * JSON-RPC over fetch の 1 往復。タイムアウト・本文上限・seam 解決・本文解放を 1 か所に閉じる。
 *
 * @param url JSON-RPC エンドポイント URL。
 * @param fetchImpl fetch 実装（未指定はグローバル `fetch`。テストで注入可能）。
 * @param id JSON-RPC リクエスト ID。
 * @param method JSON-RPC メソッド名。
 * @param params JSON-RPC パラメータ。
 * @param rejectedCode 相手が JSON-RPC error を返したときに正規化するエラーコード。
 * @returns JSON-RPC レスポンスの `result`。
 * @throws 通信失敗 / タイムアウト / 非 2xx / 本文の上限超過 / JSON 不正のとき `1021`、
 *         JSON-RPC error 応答のとき `rejectedCode`。
 */
export async function requestJsonRpc(
  url: string,
  fetchImpl: FetchLike | undefined,
  id: number,
  method: string,
  params: readonly unknown[],
  rejectedCode: ErrorCode,
): Promise<unknown> {
  // `fetchImpl` は常に own プロパティとして載せる（省略時も）。空リテラルを渡すと
  // `Object.prototype.fetchImpl` の汚染値を掴み、リクエストごと攻撃者へ委譲される。
  const { doFetch, receiver } = resolveInjectedFetch({ fetchImpl });
  const controller = new AbortController();
  // 本文の読み出しまでを 1 つのタイムアウトで覆う（`clearTimeout` は本文読了後）。
  const timer = setTimeout(() => controller.abort(), JSON_RPC_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      // 裸呼び出しにしない（`this` 参照つき実装が壊れ、その TypeError が幻の通信障害として
      // `CHAIN_SUBMIT_FAILED` へ正規化される。`fetch-di.ts` の規則 2）。
      response = await doFetch.call(receiver, url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        // 3xx に追従して署名済み UserOperation 等を別ホストへ再送しない。
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      // トランスポート失敗（DNS / 接続断 / タイムアウト abort 等）。本文・URL は伝播させない。
      throw transportFailure();
    }
    // リダイレクト（3xx / opaqueredirect / 非公開な最終 URL）は本文を読まずトランスポート失敗へ倒す。
    // ループバック RPC は初回 URL だけの例外で、リダイレクトは追従しない。
    if (isRedirectedPostResponse(url, response)) {
      throw transportFailure();
    }
    // 自己申告の `content-length` で早期に落とし、偽装された場合も実バイト数で打ち切る。
    if (!response.ok || declaresOversizedBody(response)) {
      throw transportFailure();
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      throw transportFailure();
    }
    if (text === undefined) {
      throw transportFailure();
    }
    const body = parseJsonRpcBody(text);
    if (body.error !== undefined) {
      // 相手が JSON-RPC error を返した = 要求の拒否。本文にアドレス等を含み得るため
      // cause / message は渡さない。
      throw new VericertsError(rejectedCode);
    }
    return body.result;
  } finally {
    clearTimeout(timer);
    discardBody(response);
  }
}
