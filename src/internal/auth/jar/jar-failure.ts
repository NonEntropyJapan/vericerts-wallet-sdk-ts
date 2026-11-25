/**
 * JAR（`request_uri` 参照形式）経路の失敗を `OID4VP_REQUEST_PARSE_FAILED`（8030）へ正規化する。
 *
 * **なぜ独立モジュールにするか。** 取得（`fetch-jar.ts`）と署名検証（`jar-signature.ts` /
 * `jar-x5c.ts`）は互いを参照する関係にあり（取得が検証を呼ぶ）、失敗の正規化をどちらかの
 * ファイルに置くと逆向きの import が要る。1 つの経路の失敗面が 2 つのコードへ分かれると
 * 「取得の失敗は 8030 だが署名検証の失敗は別コード」という差が生まれ、呼び出し側は
 * 「この提示要求は成立しない」という同じ結末に 2 通りの分岐を書くことになる。
 *
 * セキュリティ上の注意: `reason` は**固定の識別子のみ**で、
 * `request_uri`・Request Object 本文（JWT）・証明書 DER・`cause` は一切載せない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';

/**
 * JAR 経路の失敗を 8030 へ正規化する。
 *
 * @param reason 固定の失敗識別子（`non_https_request_uri` / `jar_signature_invalid` 等）。
 * @returns `OID4VP_REQUEST_PARSE_FAILED`（8030）の `VericertsError`。
 */
export function jarFailure(reason: string): VericertsError {
  return new VericertsError(ErrorCodes.OID4VP_REQUEST_PARSE_FAILED, { context: { reason } });
}
