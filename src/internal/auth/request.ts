/**
 * OID4VP Authorization Request パース（URL クエリ / JAR）。
 *
 * OpenID for Verifiable Presentations 1.0（Draft 24+）準拠。
 *
 * 本モジュールは Authorization Request の **パースと構造正規化** を担う:
 *
 * - `openid4vp://?response_type=vp_token&...` 形式のクエリパラメータをパースする。
 * - `dcql_query`（url-encoded JSON）を `DcqlQuery` 構造へデコードする（評価は `dcql.ts`）。
 * - `request_uri` 参照形式（JAR）の場合、取得した JAR JWT のクレームを Request 構造へ展開する
 *   （実装は `jar/parse-jar.ts`、本ファイルは再エクスポートのみ。1 ファイル 300 行の Linterly
 *   上限のため分離。`jar/` 配下に置くのは他の JAR 関連モジュールと同じ場所に集約するため）。
 * - `transaction_data`（EUDI / HAIP）を生 base64url 文字列配列へ正規化する。
 *
 * `PresentationRequest` 型とクレーム非依存の構築ロジック（`buildRequest`）は `request-common.ts`
 * が持つ（クエリ形式・JAR 形式の両方から使う）。
 *
 * スコープ外（別モジュール／別フェーズの責務）:
 * - `request_uri` の HTTP 取得。本モジュールは取得済み JAR JWT 文字列を受け取る**同期の純粋関数**に
 *   留め、取得と参照形式の統合は `jar/`（`fetchJAR` / `parsePresentationRequest`）が担う。
 * - JAR JWS 署名検証・x5c / Trust Anchor チェーン検証。本モジュールは
 *   解析だけを担い、検証は `auth/jar/jar-signature.ts` が行う（`fetchJAR` /
 *   `parsePresentationRequest` が取得直後・解析前に通す）。
 * - VP Token 構築・direct_post 送信。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に Request 本文や JWT を含めない。
 * - `response_uri` のドメインが `client_id` と一致することを検証する。
 * - `response_uri` のスキームが `https` であることを検証する。同一オリジンでも
 *   `http://` なら VP Token が平文で送られるため、origin 一致検査だけでは不十分。
 */

import { ErrorCodes, VericertsError } from '../errors.js';
import { parseJsonWithoutPrototype } from '../prototype-safety/parse-json.js';
import { parseDcqlQuery } from './dcql/dcql.js';
import { extractQuery, requestUriReferenceOf } from './oid4vp/oid4vp-request-query.js';
import { buildRequest, type PresentationRequest } from './request-common.js';
import { parseTransactionDataQueryParam } from './request-v2.js';

/** OID4VP Authorization Request のカスタムスキーム。 */
export const OID4VP_SCHEME = 'openid4vp';

export { parseJarRequest } from './jar/parse-jar.js';
export type { PresentationRequest } from './request-common.js';

/** url-encoded JSON パラメータを object へデコードする。 */
function decodeJsonParam(value: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(value);
  } catch {
    // JWT / 本文を漏らさないため cause は握りつぶす。
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  return parsed as Record<string, unknown>;
}

/**
 * OID4VP Authorization Request URI（クエリパラメータ形式）をパースする。
 *
 * 本関数は**同期**であり `request_uri` 参照形式（JAR）を解決できない（HTTP 取得が必要）。
 * `request_uri` が空白のみでない値で載っている URI は、直接パラメータが併記されていても
 * `OID4VP_REQUEST_PARSE_FAILED`（8030、`reason: 'request_uri_reference'`）を投げる
 * （RFC 9101 §6.3 は Request Object 側を優先すると定めるが、本関数はそれを取得できないため
 * fail-closed に落とす。黙って直接形式として扱うと、署名済み Request Object を捨てて署名の無い
 * クエリパラメータを採用することになる）。参照形式も含めて 1 本で扱いたい場合は
 * `parsePresentationRequest` を、取得済みの JAR JWT を渡す場合は `parseJarRequest` を使う。
 *
 * @param requestUri `openid4vp://?response_type=vp_token&...` 形式の URI。
 * @returns 正規化された `PresentationRequest`。
 * @throws 必須パラメータ欠落 / DCQL 構文エラー / ドメイン不一致時（VericertsError、code `8030`）。
 */
export function parseAuthorizationRequest(requestUri: string): PresentationRequest {
  const query = extractQuery(requestUri);

  // 参照形式（JAR）は同期の本関数では解決できない（HTTP 取得が必要）。判定は直接形式と参照形式で
  // 共有し（`oid4vp-request-query.ts`）、片方だけ条件がずれて署名の無いクエリが採用される事故を防ぐ。
  // 直接パラメータとの混在も RFC 9101 §6.3 のとおり参照形式なので、ここで fail-closed に落とす
  // （取得できないまま直接形式として通すと署名の無いクエリを採用してしまう）。参照形式を処理したい
  // 呼び出し側は `parsePresentationRequest`（`jar/`）を使う。
  if (requestUriReferenceOf(query) !== undefined) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, {
      context: { reason: 'request_uri_reference' },
    });
  }

  const dcqlRaw = query.get('dcql_query');
  const pdRaw = query.get('presentation_definition');
  const cmRaw = query.get('client_metadata');
  const txRaw = query.get('transaction_data');

  return buildRequest({
    responseType: query.get('response_type'),
    clientId: query.get('client_id'),
    responseMode: query.get('response_mode'),
    responseUri: query.get('response_uri'),
    nonce: query.get('nonce'),
    state: query.get('state'),
    dcqlQuery: dcqlRaw !== null ? parseDcqlQuery(decodeJsonParam(dcqlRaw)) : undefined,
    presentationDefinition: pdRaw !== null ? decodeJsonParam(pdRaw) : undefined,
    clientMetadata: cmRaw !== null ? decodeJsonParam(cmRaw) : undefined,
    transactionData: txRaw !== null ? parseTransactionDataQueryParam(txRaw) : undefined,
    requiredLoA: query.get('required_loa') ?? undefined,
  });
}
