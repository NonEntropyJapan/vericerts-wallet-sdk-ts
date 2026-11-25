/**
 * OID4VP PAR レスポンス JSON（RFC 9126 §2.2 の `201 { request_uri, expires_in }`）の検証・正規化。
 *
 * 応答形式は OID4VCI の PAR と共通（RFC 9126 §2.2）。呼び出し側が OID4VP 経路の失敗を特定できるよう、
 * エラーは `OID4VP_PAR_REQUEST_FAILED`（8031）で返す。
 *
 * `par.ts` が `parseJsonWithoutPrototype(await response.text())` で読むため本関数の入力は
 * **`null` プロトタイプ**だが、メンバは自身のプロパティに限って読む。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { isNonEmptyString, toFiniteNumber } from '../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { OID4VPPARResponse } from './par.js';

/**
 * OID4VP PAR レスポンス JSON を `OID4VPPARResponse` へマッピング・検証する。
 *
 * `request_uri`（非空文字列）・`expires_in`（有限数）の欠落・型不正は
 * `OID4VP_PAR_REQUEST_FAILED`（8031）に正規化する。両メンバとも own 限定で読むため、
 * `Object.prototype` 汚染下でも欠落した応答は欠落として 8031 へ倒れる（fail-closed）。
 */
export function parseOID4VPPARResponse(body: unknown): OID4VPPARResponse {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new VericertsError(ErrorCodes.OID4VP_PAR_REQUEST_FAILED);
  }
  const requestUriValue = ownProperty<unknown>(body, 'request_uri');
  const requestUri = isNonEmptyString(requestUriValue) ? requestUriValue : null;
  const expiresIn = toFiniteNumber(ownProperty<unknown>(body, 'expires_in'));
  if (requestUri === null || expiresIn === null) {
    throw new VericertsError(ErrorCodes.OID4VP_PAR_REQUEST_FAILED);
  }
  return { request_uri: requestUri, expires_in: expiresIn };
}
