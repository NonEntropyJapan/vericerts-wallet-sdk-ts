/**
 * grant の認可を担う Authorization Server の決定（OID4VCI 1.0 §4.1.1）。
 *
 * `authorization_code` / `pre-authorized_code` の両 grant は `authorization_server` を任意で
 * 宣言できる。経路ごとに選び方が違うと、片方だけ「複数 AS を告知する Issuer で先頭へ送る」
 *・「宣言値を照合せず採用する」といった欠陥が残るため、規則を 1 か所に置いて
 * `receiveCredential`（facade）と EUDI `receivePID` / `receiveEAA` が共有する。
 *
 * 規則:
 *
 * - grant が `authorization_server` を宣言する場合、その値は Issuer Metadata の
 *   `authorization_servers` の**いずれかと一致しなければならない**（§4.1.1）。一致しなければ
 *   fail-closed（`authorization_server_not_declared`）。
 * - `authorization_servers` が**未告知**なら、宣言値を照合する術が無いので同じく fail-closed。
 *   「照合できないから採用する」は照合の省略と同義である。
 * - 宣言が無い場合にのみ Issuer Metadata の告知の先頭、それも無ければ `credential_issuer` 自身
 *   （OID4VCI の既定。AS を別立てしない Issuer がこれに当たる）へ落とす。
 *
 * **Offer は攻撃者が影響し得る入力なので照合を省けない。** 正規の `credential_issuer` と
 * 攻撃者の `authorization_server` を組み合わせた Offer を通すと、AS Metadata の取得先が攻撃者に
 * なり、`pre-authorized_code` / `tx_code` / `client_assertion` が攻撃者の Token Endpoint へ送出される。
 * 判定は AS Metadata を引く前に行うため、拒否した宛先へは HTTP が 1 度も発生しない。
 *
 * 比較規則は {@link sameIdentifier}。**返すのは宣言値そのまま**（正規化した値ではない）。
 * いずれの経路でも HTTPS は Metadata 取得側が課す。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  AUTHORIZATION_SERVERS_LIMITS,
  MAX_AUTHORIZATION_SERVER_LENGTH,
} from '../../../primitives/oid4vci-input-limits.js';
import { trimTrailingSlashes } from '../../../primitives/trim-trailing-slashes.js';
import { ownProperty } from '../../../prototype-safety/own-property.js';

/**
 * grant の `authorization_server` と Issuer Metadata の `authorization_servers` から AS を決める。
 *
 * @param grant `authorization_code` または `pre-authorized_code` の grant（`authorization_server` は own 限定で読む）。
 * @param authorizationServers Issuer Metadata が告知した AS 識別子群（未告知なら `undefined`）。
 * @param credentialIssuer Offer の `credential_issuer`（宣言も告知も無いときの既定の AS）。
 * @returns AS の識別子。
 * @throws 宣言値が告知と照合できない場合（VericertsError、code `8010`、
 *         `reason: 'authorization_server_not_declared'`）。
 */
export function resolveAuthorizationServer(
  grant: object,
  authorizationServers: readonly string[] | undefined,
  credentialIssuer: string,
): string {
  const declared = ownProperty<string>(grant, 'authorization_server');
  if (declared === undefined) {
    return authorizationServers?.[0] ?? credentialIssuer;
  }
  // 宣言値の正規化はループの外で 1 回だけ行い、件数・長さの上限超過は fail-closed。
  const target = trimTrailingSlashes(declared);
  const matches =
    declared.length <= MAX_AUTHORIZATION_SERVER_LENGTH &&
    authorizationServers !== undefined &&
    authorizationServers.length <= AUTHORIZATION_SERVERS_LIMITS.maxCount &&
    authorizationServers.some(
      (server) =>
        server.length <= MAX_AUTHORIZATION_SERVER_LENGTH && trimTrailingSlashes(server) === target,
    );
  if (!matches) {
    throw new VericertsError(ErrorCodes.TOKEN_REQUEST_FAILED, {
      context: { reason: 'authorization_server_not_declared' },
    });
  }
  return declared;
}
