/**
 * PAR レスポンス JSON（RFC 9126 §2.2 の `201 { request_uri, expires_in }`）の検証・正規化。
 *
 * `par.ts` から切り出した応答パース層。切り出しの理由は 2 つある。
 * (1) 送信側（`pushAuthorizationRequest`）と受信側で責務が異なり、応答の型検証だけを
 *     単体で読めるようにするため。
 * (2) `par.ts` が 1 ファイル 300 行の上限に達しており、同ファイルへ積み増すと
 *     上限を超えるため。
 *
 * PAR 応答は `par.ts` が `parseJsonWithoutPrototype(await response.text())` で読むため
 * `Object.prototype` を継承しない。パース境界を経ずに渡された応答でも同じ保証を得るため、
 * 応答メンバは**自身のプロパティに限って読む**。
 * 鎖読みへ戻すと、パース境界を通らない値の流入時に AS が `{}` を返しただけでも
 * `Object.prototype.request_uri` の汚染値が「AS が払い出した request_uri」として採用され、
 * 後続の `buildAuthorizationUrl` が攻撃者の `request_uri` を front-channel の認可 URL に載せる。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { isNonEmptyString, toFiniteNumber } from '../../../prototype-safety/non-empty-string.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { PARResponse } from './par.js';

/**
 * PAR レスポンス JSON を `PARResponse` へマッピング・検証する。
 *
 * `request_uri`（非空文字列）・`expires_in`（有限数）の欠落・型不正は
 * `TOKEN_REQUEST_FAILED`（8010）に正規化する。両メンバとも own 限定で読むため、
 * `Object.prototype` 汚染下でも欠落した応答は欠落として 8010 へ倒れる（fail-closed）。
 */
export function parsePARResponse(body: unknown): PARResponse {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  const requestUriValue = ownProperty<unknown>(body, 'request_uri');
  const requestUri = isNonEmptyString(requestUriValue) ? requestUriValue : null;
  const expiresIn = toFiniteNumber(ownProperty<unknown>(body, 'expires_in'));
  if (requestUri === null || expiresIn === null) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED);
  }
  return { request_uri: requestUri, expires_in: expiresIn };
}
