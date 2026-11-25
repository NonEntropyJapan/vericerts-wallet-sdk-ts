/**
 * OID4VP 経路の PAR（Pushed Authorization Request, RFC 9126）クライアントの sub-barrel。
 *
 * - par.ts:      `pushAuthorizationRequestForPresentation`（Verifier への push）と型定義
 *                （`OID4VPPARRequest` / `OID4VPPARResponse`）。
 * - response.ts: PAR 応答 JSON の検証・正規化（`parseOID4VPPARResponse`）。
 * - params.ts:   送信するワイヤパラメータの固定値（`response_type` / `code_challenge_method`）。
 */

export type { OID4VPPARRequest, OID4VPPARResponse } from './par.js';
export { pushAuthorizationRequestForPresentation } from './par.js';
