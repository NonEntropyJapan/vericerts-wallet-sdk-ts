/**
 * OID4VCI Nonce Endpoint クライアント（`c_nonce` の事前取得）。
 *
 * `PIDReceiveOptions.walletAttestation` で用いる WUA-PoP の `nonce` には AS 発行の `c_nonce` を使う。
 *
 * **なぜ必要か。** Wallet Attestation を添付する受領では、Token Request を認証する WUA-PoP に
 * AS 発行の `c_nonce` を載せなければならない。ところが pre-authorized_code フローの Token Request
 * は AS への**最初の**要求であり、`c_nonce` はその応答で初めて返る。つまり「その Token Request を
 * 認証するための nonce」を Token Request の応答から得ることはできない。OID4VCI の Nonce Endpoint
 * はこの循環を断つために存在し、Token Request の**前に** `c_nonce` を払い出す。
 *
 * ここで自家製の乱数を nonce に用いると、AS 側は自分が発行していない値を検証できず、
 * WUA-PoP のリプレイ防止（AS が払い出した値であることの確認）が成立しない。したがって
 * `nonce_endpoint` を告知していない Issuer に対しては、仕様に反する PoP を送らず
 * 呼び出し側へ失敗を返す（判断は `receive.ts`）。
 *
 * セキュリティ上の注意:
 * - 例外の `context` は固定識別子のみ。URL・レスポンス本文・`c_nonce`・`cause` を載せない。
 * - `c_nonce` 自体は秘密ではないが、応答本文にはエラー詳細が含まれ得るため読み取らない。
 * - 本文には 1 MiB の上限を課す（`http/body-limit.ts`）。タイムアウトだけでは 10 秒ぶんの巨大な
 *   本文を確保でき、モバイルウォレットではメモリ枯渇になり得る。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { FetchLike } from '../../../fetch-di.js';
import { resolveInjectedFetch } from '../../../fetch-di.js';
import {
  declaresOversizedBody,
  discardBody,
  readBodyWithinLimit,
} from '../../../http/body-limit.js';
import { isPublicHttpsUrl, isRedirectedResponse } from '../../../http/public-https-url.js';
import { isNonBlankString } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../../prototype-safety/parse-json.js';

/** Nonce Endpoint 要求のタイムアウト（ミリ秒）。受領経路の他要求と揃えて 10 秒。 */
const NONCE_REQUEST_TIMEOUT_MS = 10_000;

/**
 * Nonce 取得の失敗を `TOKEN_REQUEST_FAILED`（8010）へ正規化する。
 *
 * Token Request の直前段であり、失敗すると access_token を取得できない点で同じ失敗面に属する。
 * `reason` は固定識別子のみ。
 */
function nonceFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED, { context: { reason } });
}

/**
 * Nonce Endpoint から `c_nonce` を取得する。
 *
 * `clearTimeout` は**本文を読み終えてから**行う（応答ヘッダだけ先に返して本文を引き延ばす
 * 相手に無限に待たされないため。`credential/json-schema/fetch-document.ts` と同じ方針）。
 *
 * @param nonceEndpoint Issuer Metadata の `nonce_endpoint`（HTTPS の絶対 URL）。
 * @param fetchImpl HTTP 呼び出しの差し替えシーム。省略時はグローバル `fetch`。
 * @returns AS が払い出した `c_nonce`。
 * @throws 非 HTTPS / 通信失敗 / タイムアウト / 非 2xx / リダイレクト降格 / 本文の上限超過 /
 *         JSON 不正 / `c_nonce` 欠落の場合（VericertsError、code `8010`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export async function requestCNonce(nonceEndpoint: string, fetchImpl?: FetchLike): Promise<string> {
  if (!isPublicHttpsUrl(nonceEndpoint)) {
    throw nonceFailure('non_https_nonce_endpoint');
  }
  const { doFetch, receiver } = resolveInjectedFetch({ fetchImpl });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NONCE_REQUEST_TIMEOUT_MS);
  // 読まずに失敗へ倒す経路でも本文を解放できるよう、`finally` から見える位置で宣言する。
  let response: Response | undefined;
  try {
    try {
      response = await doFetch.call(receiver, nonceEndpoint, {
        method: 'POST',
        headers: { Accept: 'application/json' },
        // OID4VCI の Nonce Endpoint は本文を取らない。`FetchLike` が body を要求するため空文字。
        body: '',
        // 3xx に追従して別ホストへ再送しない。
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch {
      throw nonceFailure('nonce_fetch_failed');
    }
    // WUA-PoP に使う nonce の取得ではリダイレクトを拒否する。
    if (isRedirectedResponse(response)) {
      throw nonceFailure('insecure_redirect');
    }
    if (!response.ok) {
      throw nonceFailure('nonce_http_error');
    }
    // 自己申告の `content-length` で早期に落とし、偽装された場合も実バイト数で打ち切る
    // （`c_nonce` は数十バイトで足り、巨大な応答は DoS 以外の意味を持たない）。
    if (declaresOversizedBody(response)) {
      throw nonceFailure('oversized_body');
    }
    let text: string | undefined;
    try {
      text = await readBodyWithinLimit(response);
    } catch {
      throw nonceFailure('nonce_fetch_failed');
    }
    if (text === undefined) {
      throw nonceFailure('oversized_body');
    }
    let parsed: unknown;
    try {
      parsed = parseJsonWithoutPrototype(text);
    } catch {
      throw nonceFailure('invalid_nonce_response');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw nonceFailure('invalid_nonce_response');
    }
    // 純データのワイヤパラメータなので own 限定で読む（多層防御。応答は null プロトタイプ）。
    const cNonce = ownProperty<unknown>(parsed, 'c_nonce');
    if (!isNonBlankString(cNonce)) {
      throw nonceFailure('missing_c_nonce');
    }
    return cNonce;
  } finally {
    clearTimeout(timer);
    // 本文を読まずに throw した経路が接続を掴んだまま残らないようにする（読了後は no-op）。
    discardBody(response);
  }
}
