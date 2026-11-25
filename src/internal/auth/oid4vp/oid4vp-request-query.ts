/**
 * OID4VP Authorization Request のクエリ抽出と `request_uri` 参照形式の判定。
 *
 * OID4VP の提示要求には 2 つの形が有り、両者は**同じクエリ文字列の中で見分ける**しかない。
 *
 * - 直接形式: `response_type=vp_token&client_id=…&dcql_query=…` がクエリに直接載る。
 * - 参照形式（JAR / RFC 9101）: `request_uri=https://…` だけが載り、実パラメータは
 *   `request_uri` から取得する Request Object（JWS）の中にある（HAIP §5.1 が必須とする形）。
 *
 * この見分けを担う入口は 2 つある。同期の `parseAuthorizationRequest`（`request.ts`）は
 * 参照形式を扱えないため `8030` で拒否し、非同期の `parsePresentationRequest`（`jar/`）は
 * 参照形式を取得して解析へ回す。**判定が 2 か所に複製されると片方だけ条件がずれる**:
 * 参照形式の判定が緩い側では「`request_uri` も `response_type` も載った要求」で
 * `request_uri` が黙って捨てられ、Verifier が署名した Request Object ではなく**署名の無い
 * クエリパラメータ**（攻撃者が deep link で書き換えられる側）が採用されうる。逆に厳しい側では
 * 正当な直接形式が拒否される。したがって判定を本モジュール 1 か所に集約し、両入口から参照する。
 *
 * 混在（`request_uri` と直接パラメータの両方が載る形）は **RFC 9101 §6.3 の優先順位**に従い
 * 参照形式として扱う。同 §5.2.1 は互換性のため Request Object の内容をクエリに重複して送ることを
 * 認め、§6.3 は「Request Object 内のパラメータのみを使わなければならない」と定めるため、
 * `response_type=vp_token` を併記する準拠 Verifier は実在し得る。混在を直接形式として扱うと、
 * まさに上段が危険と名指しした「署名済み Request Object を黙って捨て、署名の無いクエリを採用する」
 * 状態になる。
 *
 * 本モジュールは HTTP 取得を行わず、依存は `errors.ts` と `non-empty-string.ts` の 2 つだけである
 * （`request.ts` からも `jar/` からも参照できるようにするため、どちらにも依存しない位置に置く）。
 *
 * セキュリティ上の注意: 例外メッセージ・`context` に Request 本文・
 * `request_uri`・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonBlankString } from '../../prototype-safety/non-empty-string.js';

/**
 * Authorization Request のクエリ文字列を抽出する（スキーム有無の両対応）。
 *
 * `openid4vp://?…` / `openid4vp://authorize?…` / 素の `?…` / `key=value&…` を許容する。
 *
 * @param requestUri Authorization Request URI（またはクエリ文字列そのもの）。
 * @returns パース済みのクエリパラメータ。
 * @throws クエリが空の場合（VericertsError、code `8030`）。
 */
export function extractQuery(requestUri: string): URLSearchParams {
  const queryStart = requestUri.indexOf('?');
  const raw = queryStart >= 0 ? requestUri.slice(queryStart + 1) : requestUri;
  if (raw.length === 0) {
    throw new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED);
  }
  return new URLSearchParams(raw);
}

/**
 * クエリが `request_uri` 参照形式（JAR）かを判定し、参照先 URL を返す。
 *
 * **`request_uri` が空白のみでない値で載っていれば常に参照形式と見なす**（直接パラメータの併記は
 * 問わない）。非空判定はコードベース共通の `isNonBlankString`（`non-empty-string.ts`）に委ね、
 * 空文字と空白のみ（NBSP / 全角スペースを含む）はどちらも「載っていない」として直接形式の
 * 必須パラメータ検証へ回す。空白のみを参照形式と見なすと、取得もできない URL で
 * `request_uri_reference` を投げるだけになり、直接形式として本来受け付けられる要求も
 * 検証に到達しない。
 * 根拠は RFC 9101（OID4VP が署名要求で規範参照する JAR 仕様）である: §5.2.1 は互換性のため
 * Request Object の内容をクエリへ重複して送ることを認めており、§6.3 は受け取り側が
 * **Request Object 内のパラメータのみを使わなければならない**と優先順位を定める。したがって
 * `request_uri` と `response_type` の混在は準拠 Verifier が現に送り得る形であり、直接形式として
 * 扱うと Verifier が署名した Request Object を取得せず黙って捨て、**署名の無いクエリパラメータ**
 * （deep link で書き換えられる側）を DCQL 評価と VP 送信先決定に採用してしまう。
 *
 * 判定は両入口で共有するが、混在に対する**扱いは入口の能力で分かれる**（判定のずれではない）:
 * 同期の `parseAuthorizationRequest` は HTTP 取得ができないため `8030`
 * （`reason: 'request_uri_reference'`）で fail-closed に拒否し、非同期の
 * `parsePresentationRequest` は取得して署名済み Request Object を優先する。
 *
 * @param query `extractQuery` が返したクエリパラメータ。
 * @returns 参照形式なら `request_uri` の値、そうでなければ（未指定・空文字・空白のみ）`undefined`。
 */
export function requestUriReferenceOf(query: URLSearchParams): string | undefined {
  const value = query.get('request_uri');
  return isNonBlankString(value) ? value : undefined;
}
