/**
 * OID4VCI Authorization Code Flow の認可 URL 構築。
 *
 * `pushAuthorizationRequest`（`par/par.ts`）が返す `request_uri` と `client_id`
 * から、ブラウザ / Custom Tab で開く AS の認可 URL を組み立てる。PAR とは責務が異なる
 * （push は back-channel の HTTP 呼び出し、本モジュールは front-channel へ渡す URL の組み立て）
 * ため独立モジュールとする。
 *
 * セキュリティ上の注意: 認可 URL は front-channel（ブラウザのアドレスバー・
 * Referer・履歴）に露出するため、載せるのは RFC 9126 が許す `client_id` と `request_uri` のみとし、
 * エンドポイントが HTTPS でない場合は組み立てを拒否する。例外メッセージ・`context` に
 * `request_uri` を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';
import { isHttpsUrl } from './oid4vci-url-guards.js';

/**
 * PAR で取得した `request_uri` と `client_id` から AS の認可 URL を組み立てる。
 *
 * RFC 9126 のとおり、フロントチャネルに載せるのは `client_id` と `request_uri` のみとする
 * （他の認可パラメータは PAR で push 済み）。生成した URL をブラウザ / Custom Tab で開く。
 *
 * @param authorizationEndpoint AS の Authorization Endpoint URL。
 * @param clientId Wallet の client_id（PAR で push したものと同一）。
 * @param requestUri `pushAuthorizationRequest` が返した request_uri。
 * @returns `?client_id=<client_id>&request_uri=<request_uri>` を持つ認可 URL 文字列。
 * @throws authorizationEndpoint が HTTPS でない（フロントチャネルの傍受防止）、
 *         または client_id / request_uri が空の場合（VericertsError, code `8010`）。
 *
 * @experimental 挙動・シグネチャが変わることがある（v1.0 で `@stable` 昇格予定）。
 */
export function buildAuthorizationUrl(
  authorizationEndpoint: string,
  clientId: string,
  requestUri: string,
): string {
  // 認可 URL は HTTPS でブラウザに渡す前提。不正・非 HTTPS は push 結果を使えないため失敗扱い。
  if (!isHttpsUrl(authorizationEndpoint)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  if (!isNonBlankString(clientId) || !isNonBlankString(requestUri)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  const url = new URL(authorizationEndpoint);
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('request_uri', requestUri);
  return url.toString();
}
