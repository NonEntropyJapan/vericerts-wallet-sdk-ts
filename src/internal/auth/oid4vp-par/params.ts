/**
 * OID4VP 経路の PAR が送信するワイヤパラメータの固定値。
 *
 * `pushAuthorizationRequestForPresentation` が呼び出し側の指定を受け付けずに固定で送る値
 * （`response_type` / `code_challenge_method`）を集約する。OID4VCI 側の同名モジュール
 * （`oid4vci/par/params.ts`）と値の一部（`code_challenge_method`）は同じだが、`response_type` は
 * OID4VP の Authorization Request が定める `vp_token` になるため異なる。
 * OID4VCI と OID4VP の値はそれぞれのモジュールで定義する。
 */

/** `response_type=vp_token`（OID4VP の Authorization Request）。 */
export const RESPONSE_TYPE_VP_TOKEN = 'vp_token' as const;

/** PKCE code_challenge_method（本 SDK は S256 のみ）。 */
export const CODE_CHALLENGE_METHOD_S256 = 'S256' as const;
