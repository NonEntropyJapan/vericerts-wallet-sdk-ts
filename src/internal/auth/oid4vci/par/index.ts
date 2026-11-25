/**
 * OID4VCI PAR（Pushed Authorization Request, RFC 9126）クライアントの sub-barrel。
 *
 * - par.ts:      `pushAuthorizationRequest`（PAR エンドポイントへの push）と型定義
 *                （`PARRequest` / `PARResponse` / `OAuth2AuthzDetails`）。
 * - response.ts: PAR 応答 JSON の検証・正規化（`parsePARResponse`）。
 * - params.ts:   送信するワイヤパラメータの固定値（`response_type` / `code_challenge_method`）。
 */

export type { OAuth2AuthzDetails, PARRequest, PARResponse } from './par.js';
export { pushAuthorizationRequest } from './par.js';
