/**
 * `request_uri` 参照形式（JAR / RFC 9101）の取得と提示要求の単一入口（sub-barrel）。
 *
 *
 * - fetch-jar.ts:            `request_uri` から Request Object（JWS）を取得・検証して正規化する。
 * - presentation-request.ts: 直接形式 / 参照形式のどちらの提示要求 URI も 1 本で解析する。
 * - jar-signature.ts:        JAR JWS 署名検証（`x5c` / Trust Anchor / `iss == client_id`）。
 * - jar-x5c.ts:              JOSE Header の `x5c` 抽出と JWS `alg` の許可リスト。
 * - jar-failure.ts:          取得・検証の失敗を `8030` へ正規化する（両者が共有する失敗面）。
 *
 * 参照形式かどうかの判定は `../oid4vp/oid4vp-request-query.ts` に集約されており（同期の
 * `parseAuthorizationRequest` と共有する）、本ディレクトリでは複製しない。
 */

export { type FetchJarOptions, fetchJAR } from './fetch-jar.js';
export { type JarTrustOptions, verifyJarSignature } from './jar-signature.js';
export {
  type PresentationRequestOptions,
  parsePresentationRequest,
} from './presentation-request.js';
