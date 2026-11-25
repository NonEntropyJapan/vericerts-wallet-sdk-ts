/**
 * OID4VCI Authorization Code Flow の URL / 文字列ガード。
 *
 * PAR push（`par/par.ts`）と認可 URL 構築（`oid4vci-authz-url.ts`）は
 * どちらも「HTTPS でないエンドポイントを拒否する」という同じ入口検査を必要とする。両者で判定が
 * ずれると、片方の経路だけ非 HTTPS を素通りさせて client_assertion（`<WUA>~<WUA-PoP>`）や
 * request_uri を平文で送出しうるため、判定を 1 か所に集約する。
 *
 * **判定の実体は横断ヘルパー `internal/https-url.ts` にある。** `eudi`（Domain）の WUA 取得・
 * Issuer Metadata / Nonce Endpoint 取得も同じ検査を必要とし、本モジュール（Protocol）を直接
 * 参照すると Domain → Protocol の逆方向依存になるため、`fetch-di.ts` と同じ理由で
 * 横断へ移した。本モジュールは OID4VCI 側の参照名を
 * 保つための再エクスポートに徹し、判定を複製しない。
 *
 * 空文字・空白のみのパラメータの拒否は `internal/prototype-safety/non-empty-string.ts` の `isNonBlankString` が
 * 担う（コードベース全体で 1 つの規則にするため）。
 */

export { isHttpsUrl } from '../../https-url.js';
