/**
 * OID4VCI PAR が送信するワイヤパラメータの固定値。
 *
 * `pushAuthorizationRequest` が呼び出し側の指定を受け付けずに固定で送る値（`response_type` /
 * `code_challenge_method`）を集約する。呼び出し側が明示指定する
 * `client_assertion_type` の標準値は既存の公開定数 `WUA_CLIENT_ASSERTION_TYPE`
 * （`internal/eudi/wua/types.ts`）が持つため、ここには重複定義しない。値の根拠が RFC / 仕様書の節に紐づくため、送信ロジック（`par.ts`）とは分けて
 * 「何を送るか」を 1 か所で読めるようにする。
 */

/** `response_type=code`（Authorization Code Flow で固定）。 */
export const RESPONSE_TYPE_CODE = 'code' as const;

/** PKCE code_challenge_method（本 SDK は S256 のみ）。 */
export const CODE_CHALLENGE_METHOD_S256 = 'S256' as const;
